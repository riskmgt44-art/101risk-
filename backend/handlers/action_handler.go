// handlers/action_handler.go 

package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/models"
	"riskmgt/utils"
)

func CreateAction(w http.ResponseWriter, r *http.Request) {
	// Get organization ID from context
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Parse request body - now matching the frontend fields
	var actionData struct {
		Title       string    `json:"title"`
		Description string    `json:"description"`
		RiskID      string    `json:"riskId"`
		Status      string    `json:"status"`
		Priority    string    `json:"priority"`
		Owner       string    `json:"owner"`
		Cost        float64   `json:"cost"`
		Progress    int       `json:"progress"`
		StartDate   string    `json:"startDate"`
		EndDate     string    `json:"endDate"`
		Notes       string    `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&actionData); err != nil {
		log.Printf("Error decoding request body: %v", err)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// Validate required fields
	if actionData.Title == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
		return
	}

	// Convert riskId string to ObjectID - handle empty string
	var riskID primitive.ObjectID
	if actionData.RiskID != "" {
		riskID, err = primitive.ObjectIDFromHex(actionData.RiskID)
		if err != nil {
			// Allow empty risk ID - not all actions need to be linked to a risk
			log.Printf("Warning: Invalid risk ID format: %s - creating action without risk link", actionData.RiskID)
			// Set riskID to NilObjectID to indicate no risk association
			riskID = primitive.NilObjectID
		} else {
			log.Printf("Creating action linked to risk ID: %s", actionData.RiskID)
		}
	} else {
		log.Printf("Creating action without risk link (no risk ID provided)")
		riskID = primitive.NilObjectID
	}

	// Parse dates (they come as strings from frontend)
	var startDate, endDate *time.Time
	if actionData.StartDate != "" {
		parsedStart, err := time.Parse("2006-01-02", actionData.StartDate)
		if err == nil {
			startDate = &parsedStart
		} else {
			log.Printf("Warning: Invalid start date format: %s", actionData.StartDate)
		}
	}
	if actionData.EndDate != "" {
		parsedEnd, err := time.Parse("2006-01-02", actionData.EndDate)
		if err == nil {
			endDate = &parsedEnd
		} else {
			log.Printf("Warning: Invalid end date format: %s", actionData.EndDate)
		}
	}

	// Create action object with all fields
	action := models.Action{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		RiskID:         riskID,
		Title:          actionData.Title,
		Description:    actionData.Description,
		Status:         actionData.Status,
		Priority:       actionData.Priority,
		Owner:          actionData.Owner,
		Cost:           actionData.Cost,
		Progress:       actionData.Progress,
		StartDate:      startDate,
		EndDate:        endDate,
		Notes:          actionData.Notes,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	// Insert into database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := actionCollection.InsertOne(ctx, action)
	if err != nil {
		log.Printf("Error inserting action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create action")
		return
	}

	// Get the inserted action
	var insertedAction models.Action
	err = actionCollection.FindOne(ctx, bson.M{"_id": result.InsertedID}).Decode(&insertedAction)
	if err != nil {
		log.Printf("Error finding inserted action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve created action")
		return
	}

	log.Printf("Created action %s for org %s (linked to risk: %v)", 
		insertedAction.ID.Hex(), orgIDHex, insertedAction.RiskID.Hex())
	
	// Get user info from context for audit log
	userIDStr, _ := r.Context().Value("userID").(string)
	userName, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)
	
	var userID primitive.ObjectID
	if userIDStr != "" {
		userID, _ = primitive.ObjectIDFromHex(userIDStr)
	}
	
	// Only create audit log if userID is valid
	if userID != primitive.NilObjectID {
		// Create audit log for the action creation
		auditLog := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         userID,
			UserEmail:      userName,
			UserRole:       userRole,
			Action:         "CREATE_ACTION",
			EntityType:     "action",
			EntityID:       insertedAction.ID,
			Details: bson.M{
				"title":    insertedAction.Title,
				"riskId":   insertedAction.RiskID.Hex(),
				"status":   insertedAction.Status,
				"priority": insertedAction.Priority,
			},
			CreatedAt: time.Now(),
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
		}
		
		// Save audit log to database
		go saveAuditLog(&auditLog)
		
		// Broadcast via WebSocket
		BroadcastAudit(&auditLog)
	}
	
	// Return the created action with proper risk ID
	utils.RespondWithJSON(w, http.StatusCreated, insertedAction)
}

func ListActions(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get filter parameters
	riskID := r.URL.Query().Get("riskId")
	status := r.URL.Query().Get("status")
	
	// Build filter
	filter := bson.M{"organizationId": orgID}
	
	if riskID != "" {
		riskObjID, err := primitive.ObjectIDFromHex(riskID)
		if err == nil {
			// Filter by risk ID
			filter["riskId"] = riskObjID
			log.Printf("Filtering actions by risk ID: %s", riskID)
		} else {
			log.Printf("Warning: Invalid risk ID in query: %s - returning empty actions", riskID)
			// If risk ID is invalid, return empty array
			utils.RespondWithJSON(w, http.StatusOK, []models.Action{})
			return
		}
	} else {
		// If no risk ID specified, also include actions with empty/null riskId
		// This allows viewing all actions when no specific risk is selected
		log.Printf("No risk ID filter - returning all actions for org")
	}
	
	if status != "" {
		filter["status"] = status
	}

	// Always return [] not null — this is the #1 cause of frontend "loading forever"
	var actions []models.Action

	cursor, err := actionCollection.Find(r.Context(), filter)
	if err != nil {
		// Collection might not exist yet — this is normal in MongoDB
		if err == mongo.ErrNoDocuments || err.Error() == "no such collection" {
			log.Printf("No actions collection or empty for org %s", orgIDHex)
		} else {
			log.Printf("Mongo Find error for actions: %v", err)
		}
		// Still return empty array — never error out on empty
		utils.RespondWithJSON(w, http.StatusOK, []models.Action{})
		return
	}
	defer cursor.Close(r.Context())

	if err = cursor.All(r.Context(), &actions); err != nil {
		log.Printf("Cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode actions")
		return
	}

	// Ensure we never return null
	if actions == nil {
		actions = []models.Action{}
	}

	log.Printf("Successfully returned %d actions for org %s (risk filter: %s)", len(actions), orgIDHex, riskID)
	utils.RespondWithJSON(w, http.StatusOK, actions)
}

// GetActionsByRiskID returns actions for a specific risk (alternative endpoint)
func GetActionsByRiskID(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get risk ID from URL path
	vars := mux.Vars(r)
	riskIDStr := vars["riskId"]
	if riskIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Risk ID is required")
		return
	}

	riskID, err := primitive.ObjectIDFromHex(riskIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid risk ID format")
		return
	}

	// Build filter for this specific risk
	filter := bson.M{
		"organizationId": orgID,
		"riskId":         riskID,
	}

	var actions []models.Action
	cursor, err := actionCollection.Find(r.Context(), filter)
	if err != nil {
		if err == mongo.ErrNoDocuments || err.Error() == "no such collection" {
			log.Printf("No actions found for risk %s in org %s", riskIDStr, orgIDHex)
		} else {
			log.Printf("Mongo Find error for actions by risk: %v", err)
		}
		utils.RespondWithJSON(w, http.StatusOK, []models.Action{})
		return
	}
	defer cursor.Close(r.Context())

	if err = cursor.All(r.Context(), &actions); err != nil {
		log.Printf("Cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode actions")
		return
	}

	if actions == nil {
		actions = []models.Action{}
	}

	log.Printf("Returned %d actions for risk %s in org %s", len(actions), riskIDStr, orgIDHex)
	utils.RespondWithJSON(w, http.StatusOK, actions)
}

// GetActionByID returns a single action by ID
func GetActionByID(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get action ID from URL path
	vars := mux.Vars(r)
	actionIDStr := vars["id"]
	if actionIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	actionID, err := primitive.ObjectIDFromHex(actionIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID format")
		return
	}

	// Find the action
	var action models.Action
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = actionCollection.FindOne(ctx, bson.M{
		"_id":            actionID,
		"organizationId": orgID,
	}).Decode(&action)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch action")
		}
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, action)
}

// UpdateAction updates an existing action
func UpdateAction(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get action ID from URL path
	vars := mux.Vars(r)
	actionIDStr := vars["id"]
	if actionIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	actionID, err := primitive.ObjectIDFromHex(actionIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID format")
		return
	}

	// Parse update data
	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Remove fields that shouldn't be updated
	delete(updateData, "_id")
	delete(updateData, "organizationId")
	delete(updateData, "createdAt")
	
	// Add updatedAt timestamp
	updateData["updatedAt"] = time.Now()

	// Parse dates if present
	if startDateStr, ok := updateData["startDate"].(string); ok && startDateStr != "" {
		if parsedStart, err := time.Parse("2006-01-02", startDateStr); err == nil {
			updateData["startDate"] = parsedStart
		} else {
			delete(updateData, "startDate")
		}
	}
	
	if endDateStr, ok := updateData["endDate"].(string); ok && endDateStr != "" {
		if parsedEnd, err := time.Parse("2006-01-02", endDateStr); err == nil {
			updateData["endDate"] = parsedEnd
		} else {
			delete(updateData, "endDate")
		}
	}

	// Handle risk ID update if present
	if riskIDStr, ok := updateData["riskId"].(string); ok && riskIDStr != "" {
		riskID, err := primitive.ObjectIDFromHex(riskIDStr)
		if err == nil {
			updateData["riskId"] = riskID
		} else {
			log.Printf("Warning: Invalid risk ID in update: %s", riskIDStr)
			delete(updateData, "riskId")
		}
	}

	// Update the action
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	update := bson.M{"$set": updateData}
	result, err := actionCollection.UpdateOne(ctx, bson.M{
		"_id":            actionID,
		"organizationId": orgID,
	}, update)

	if err != nil {
		log.Printf("Error updating action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update action")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		return
	}

	// Get the updated action
	var updatedAction models.Action
	err = actionCollection.FindOne(ctx, bson.M{"_id": actionID}).Decode(&updatedAction)
	if err != nil {
		log.Printf("Error finding updated action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve updated action")
		return
	}

	// Get user info from context for audit log
	userIDStr, _ := r.Context().Value("userID").(string)
	userName, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)
	
	var userID primitive.ObjectID
	if userIDStr != "" {
		userID, _ = primitive.ObjectIDFromHex(userIDStr)
	}
	
	// Only create audit log if userID is valid
	if userID != primitive.NilObjectID {
		// Create audit log
		auditLog := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         userID,
			UserEmail:      userName,
			UserRole:       userRole,
			Action:         "UPDATE_ACTION",
			EntityType:     "action",
			EntityID:       actionID,
			Details:        updateData, // This is already a map[string]interface{}
			CreatedAt:      time.Now(),
			IPAddress:      r.RemoteAddr,
			UserAgent:      r.UserAgent(),
		}
		
		// Save audit log to database
		go saveAuditLog(&auditLog)
		
		// Broadcast via WebSocket
		BroadcastAudit(&auditLog)
	}

	utils.RespondWithJSON(w, http.StatusOK, updatedAction)
}

// DeleteAction deletes an action
func DeleteAction(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get action ID from URL path
	vars := mux.Vars(r)
	actionIDStr := vars["id"]
	if actionIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	actionID, err := primitive.ObjectIDFromHex(actionIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID format")
		return
	}

	// First, get the action before deletion for audit log
	var action models.Action
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = actionCollection.FindOne(ctx, bson.M{
		"_id":            actionID,
		"organizationId": orgID,
	}).Decode(&action)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch action")
		}
		return
	}

	// Delete the action
	result, err := actionCollection.DeleteOne(ctx, bson.M{
		"_id":            actionID,
		"organizationId": orgID,
	})

	if err != nil {
		log.Printf("Error deleting action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete action")
		return
	}

	if result.DeletedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		return
	}

	// Get user info from context for audit log
	userIDStr, _ := r.Context().Value("userID").(string)
	userName, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)
	
	var userID primitive.ObjectID
	if userIDStr != "" {
		userID, _ = primitive.ObjectIDFromHex(userIDStr)
	}
	
	// Only create audit log if userID is valid
	if userID != primitive.NilObjectID {
		// Create audit log
		auditLog := models.AuditLog{
			ID:             primitive.NewObjectID(),
			OrganizationID: orgID,
			UserID:         userID,
			UserEmail:      userName,
			UserRole:       userRole,
			Action:         "DELETE_ACTION",
			EntityType:     "action",
			EntityID:       actionID,
			Details: bson.M{
				"title":    action.Title,
				"riskId":   action.RiskID.Hex(),
				"status":   action.Status,
			},
			CreatedAt: time.Now(),
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
		}
		
		// Save audit log to database
		go saveAuditLog(&auditLog)
		
		// Broadcast via WebSocket
		BroadcastAudit(&auditLog)
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"message":  "Action deleted successfully",
		"actionId": actionID.Hex(),
	})
}

// Helper function to save audit log to database
func saveAuditLog(auditLog *models.AuditLog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	_, err := auditLogCollection.InsertOne(ctx, auditLog)
	if err != nil {
		log.Printf("Failed to save audit log: %v", err)
	}
}


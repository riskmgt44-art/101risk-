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
		log.Printf("[ERROR] CreateAction: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] CreateAction: Invalid org ID format: %s", orgIDHex)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Parse request body - now matching the frontend fields
	var actionData struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		RiskID      string  `json:"riskId"`
		Status      string  `json:"status"`
		Priority    string  `json:"priority"`
		Owner       string  `json:"owner"`
		Cost        float64 `json:"cost"`
		Progress    int     `json:"progress"`
		StartDate   string  `json:"startDate"`
		DueDate     string  `json:"dueDate"`
		Notes       string  `json:"notes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&actionData); err != nil {
		log.Printf("[ERROR] CreateAction: Error decoding request body: %v", err)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	log.Printf("[DEBUG] CreateAction: Received data: %+v", actionData)

	// Validate required fields
	if actionData.Title == "" {
		log.Printf("[ERROR] CreateAction: Missing title")
		utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
		return
	}
	if actionData.Status == "" {
		log.Printf("[ERROR] CreateAction: Missing status")
		utils.RespondWithError(w, http.StatusBadRequest, "Action status is required")
		return
	}

	// Convert riskId string to ObjectID - handle empty string
	var riskID primitive.ObjectID
	if actionData.RiskID != "" {
		riskID, err = primitive.ObjectIDFromHex(actionData.RiskID)
		if err != nil {
			log.Printf("[WARN] CreateAction: Invalid risk ID format: %s - creating action without risk link", actionData.RiskID)
			riskID = primitive.NilObjectID
		} else {
			log.Printf("[DEBUG] CreateAction: Linked to risk ID: %s", actionData.RiskID)
		}
	} else {
		log.Printf("[DEBUG] CreateAction: Creating action without risk link")
		riskID = primitive.NilObjectID
	}

	// Parse dates (they come as strings from frontend)
	var startDate, dueDate *time.Time
	if actionData.StartDate != "" {
		parsedStart, err := time.Parse("2006-01-02", actionData.StartDate)
		if err == nil {
			startDate = &parsedStart
			log.Printf("[DEBUG] CreateAction: Parsed start date: %v", parsedStart)
		} else {
			log.Printf("[WARN] CreateAction: Invalid start date format: %s", actionData.StartDate)
		}
	}
	if actionData.DueDate != "" {
		parsedDue, err := time.Parse("2006-01-02", actionData.DueDate)
		if err == nil {
			dueDate = &parsedDue
			log.Printf("[DEBUG] CreateAction: Parsed due date: %v", parsedDue)
		} else {
			log.Printf("[WARN] CreateAction: Invalid due date format: %s", actionData.DueDate)
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
		DueDate:        dueDate,
		Notes:          actionData.Notes,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	log.Printf("[DEBUG] CreateAction: Inserting action: %+v", action)

	// Insert into database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := actionCollection.InsertOne(ctx, action)
	if err != nil {
		log.Printf("[ERROR] CreateAction: Error inserting action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create action")
		return
	}

	// Get the inserted action
	var insertedAction models.Action
	err = actionCollection.FindOne(ctx, bson.M{"_id": result.InsertedID}).Decode(&insertedAction)
	if err != nil {
		log.Printf("[ERROR] CreateAction: Error finding inserted action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to retrieve created action")
		return
	}

	log.Printf("[SUCCESS] CreateAction: Created action %s for org %s", 
		insertedAction.ID.Hex(), orgIDHex)
	
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

// FIXED: ListActions with error recovery
func ListActions(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		log.Printf("[ERROR] ListActions: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	log.Printf("[DEBUG] ListActions called for org: %s", orgIDHex)

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] ListActions: Invalid org ID format: %s", orgIDHex)
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
			filter["riskId"] = riskObjID
			log.Printf("[DEBUG] Filtering by risk ID: %s", riskID)
		}
	}
	
	if status != "" {
		filter["status"] = status
		log.Printf("[DEBUG] Filtering by status: %s", status)
	}

	log.Printf("[DEBUG] Finding actions with filter: %+v", filter)

	// Find actions
	cursor, err := actionCollection.Find(r.Context(), filter)
	if err != nil {
		log.Printf("[ERROR] Find error: %v", err)
		utils.RespondWithJSON(w, http.StatusOK, []models.Action{})
		return
	}
	defer cursor.Close(r.Context())

	var actions []models.Action
	var documentCount = 0
	var recoveredCount = 0
	
	// Iterate through cursor
	for cursor.Next(r.Context()) {
		documentCount++
		var action models.Action
		
		// Try to decode into struct
		if err := cursor.Decode(&action); err != nil {
			log.Printf("[ERROR] Failed to decode document #%d: %v", documentCount, err)
			
			// Try to recover by getting raw document and creating a minimal valid action
			var raw bson.M
			if decodeErr := cursor.Decode(&raw); decodeErr == nil {
				log.Printf("[WARN] Attempting to recover document #%d", documentCount)
				
				// Create a minimal valid action from raw data
				recovered := &models.Action{
					ID:             getObjectID(raw, "_id", primitive.NewObjectID()),
					OrganizationID: orgID,
					RiskID:         getObjectID(raw, "riskId", primitive.NilObjectID),
					Title:          getString(raw, "title", getString(raw, "description", "Recovered Action")),
					Description:    getString(raw, "description", ""),
					Status:         getString(raw, "status", "pending"),
					Priority:       getString(raw, "priority", "medium"),
					Owner:          getString(raw, "owner", ""),
					Cost:           getFloat64(raw, "cost", 0),
					Progress:       getInt(raw, "progress", 0),
					Notes:          getString(raw, "notes", ""),
					CreatedAt:      getTime(raw, "createdAt", time.Now()),
					UpdatedAt:      getTime(raw, "updatedAt", time.Now()),
				}
				
				// Handle dates
				if startDate, ok := raw["startDate"]; ok {
					if t, ok := startDate.(time.Time); ok {
						recovered.StartDate = &t
					}
				}
				
				// Try both dueDate and endDate
				if dueDate, ok := raw["dueDate"]; ok {
					if t, ok := dueDate.(time.Time); ok {
						recovered.DueDate = &t
					}
				} else if endDate, ok := raw["endDate"]; ok {
					if t, ok := endDate.(time.Time); ok {
						recovered.DueDate = &t
					}
				}
				
				actions = append(actions, *recovered)
				recoveredCount++
				log.Printf("[INFO] Successfully recovered document #%d", documentCount)
			} else {
				log.Printf("[ERROR] Could not decode raw document: %v", decodeErr)
			}
			continue
		}
		actions = append(actions, action)
	}

	if err = cursor.Err(); err != nil {
		log.Printf("[ERROR] Cursor error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Cursor error")
		return
	}

	// Ensure we never return null
	if actions == nil {
		actions = []models.Action{}
	}

	log.Printf("[SUCCESS] ListActions: Returned %d actions for org %s (processed %d documents, recovered %d)", 
		len(actions), orgIDHex, documentCount, recoveredCount)
	utils.RespondWithJSON(w, http.StatusOK, actions)
}

// Helper functions for safe data extraction
func getObjectID(raw bson.M, key string, defaultValue primitive.ObjectID) primitive.ObjectID {
	if val, ok := raw[key]; ok {
		if objID, ok := val.(primitive.ObjectID); ok {
			return objID
		}
	}
	return defaultValue
}

func getString(raw bson.M, key string, defaultValue string) string {
	if val, ok := raw[key]; ok && val != nil {
		if str, ok := val.(string); ok && str != "" {
			return str
		}
	}
	return defaultValue
}

func getFloat64(raw bson.M, key string, defaultValue float64) float64 {
	if val, ok := raw[key]; ok && val != nil {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case float32:
			return float64(v)
		}
	}
	return defaultValue
}

func getInt(raw bson.M, key string, defaultValue int) int {
	if val, ok := raw[key]; ok && val != nil {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case float32:
			return int(v)
		}
	}
	return defaultValue
}

func getTime(raw bson.M, key string, defaultValue time.Time) time.Time {
	if val, ok := raw[key]; ok && val != nil {
		if t, ok := val.(time.Time); ok {
			return t
		}
	}
	return defaultValue
}

// DebugListActions returns raw actions for debugging
func DebugListActions(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		log.Printf("[ERROR] DebugListActions: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	log.Printf("[DEBUG] DebugListActions called for org: %s", orgIDHex)

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] DebugListActions: Invalid org ID format: %s", orgIDHex)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Find all actions for this org as raw BSON
	cursor, err := actionCollection.Find(r.Context(), bson.M{"organizationId": orgID})
	if err != nil {
		log.Printf("[ERROR] DebugListActions: Find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to find actions")
		return
	}
	defer cursor.Close(r.Context())

	var results []bson.M
	if err = cursor.All(r.Context(), &results); err != nil {
		log.Printf("[ERROR] DebugListActions: Decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode actions")
		return
	}

	log.Printf("[SUCCESS] DebugListActions: Found %d raw documents", len(results))
	
	// Add debug info to response
	response := struct {
		Count   int      `json:"count"`
		Actions []bson.M `json:"actions"`
		Message string   `json:"message"`
	}{
		Count:   len(results),
		Actions: results,
		Message: "Raw actions from database",
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// GetActionsByRiskID returns actions for a specific risk (alternative endpoint)
func GetActionsByRiskID(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		log.Printf("[ERROR] GetActionsByRiskID: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] GetActionsByRiskID: Invalid org ID format: %s", orgIDHex)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get risk ID from URL path
	vars := mux.Vars(r)
	riskIDStr := vars["riskId"]
	if riskIDStr == "" {
		log.Printf("[ERROR] GetActionsByRiskID: Missing risk ID")
		utils.RespondWithError(w, http.StatusBadRequest, "Risk ID is required")
		return
	}

	riskID, err := primitive.ObjectIDFromHex(riskIDStr)
	if err != nil {
		log.Printf("[ERROR] GetActionsByRiskID: Invalid risk ID format: %s", riskIDStr)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid risk ID format")
		return
	}

	log.Printf("[DEBUG] GetActionsByRiskID: Finding actions for risk: %s", riskIDStr)

	// Build filter for this specific risk
	filter := bson.M{
		"organizationId": orgID,
		"riskId":         riskID,
	}

	var actions []models.Action
	cursor, err := actionCollection.Find(r.Context(), filter)
	if err != nil {
		if err == mongo.ErrNoDocuments || err.Error() == "no such collection" {
			log.Printf("[DEBUG] GetActionsByRiskID: No actions found for risk %s", riskIDStr)
		} else {
			log.Printf("[ERROR] GetActionsByRiskID: Find error: %v", err)
		}
		utils.RespondWithJSON(w, http.StatusOK, []models.Action{})
		return
	}
	defer cursor.Close(r.Context())

	if err = cursor.All(r.Context(), &actions); err != nil {
		log.Printf("[ERROR] GetActionsByRiskID: Decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode actions")
		return
	}

	if actions == nil {
		actions = []models.Action{}
	}

	log.Printf("[SUCCESS] GetActionsByRiskID: Returned %d actions for risk %s", len(actions), riskIDStr)
	utils.RespondWithJSON(w, http.StatusOK, actions)
}

// GetActionByID returns a single action by ID
func GetActionByID(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		log.Printf("[ERROR] GetActionByID: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] GetActionByID: Invalid org ID format: %s", orgIDHex)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get action ID from URL path
	vars := mux.Vars(r)
	actionIDStr := vars["id"]
	if actionIDStr == "" {
		log.Printf("[ERROR] GetActionByID: Missing action ID")
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	actionID, err := primitive.ObjectIDFromHex(actionIDStr)
	if err != nil {
		log.Printf("[ERROR] GetActionByID: Invalid action ID format: %s", actionIDStr)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID format")
		return
	}

	log.Printf("[DEBUG] GetActionByID: Fetching action: %s", actionIDStr)

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
			log.Printf("[ERROR] GetActionByID: Action not found: %s", actionIDStr)
			utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		} else {
			log.Printf("[ERROR] GetActionByID: Find error: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch action")
		}
		return
	}

	log.Printf("[SUCCESS] GetActionByID: Found action: %s", actionIDStr)
	utils.RespondWithJSON(w, http.StatusOK, action)
}

// UpdateAction updates an existing action
func UpdateAction(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		log.Printf("[ERROR] UpdateAction: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] UpdateAction: Invalid org ID format: %s", orgIDHex)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get action ID from URL path
	vars := mux.Vars(r)
	actionIDStr := vars["id"]
	if actionIDStr == "" {
		log.Printf("[ERROR] UpdateAction: Missing action ID")
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	actionID, err := primitive.ObjectIDFromHex(actionIDStr)
	if err != nil {
		log.Printf("[ERROR] UpdateAction: Invalid action ID format: %s", actionIDStr)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID format")
		return
	}

	// Parse update data
	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		log.Printf("[ERROR] UpdateAction: Invalid request body: %v", err)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	log.Printf("[DEBUG] UpdateAction: Updating action %s with data: %+v", actionIDStr, updateData)

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
			log.Printf("[DEBUG] UpdateAction: Parsed start date: %v", parsedStart)
		} else {
			log.Printf("[WARN] UpdateAction: Invalid start date format: %s", startDateStr)
			delete(updateData, "startDate")
		}
	}
	
	if dueDateStr, ok := updateData["dueDate"].(string); ok && dueDateStr != "" {
		if parsedDue, err := time.Parse("2006-01-02", dueDateStr); err == nil {
			updateData["dueDate"] = parsedDue
			log.Printf("[DEBUG] UpdateAction: Parsed due date: %v", parsedDue)
		} else {
			log.Printf("[WARN] UpdateAction: Invalid due date format: %s", dueDateStr)
			delete(updateData, "dueDate")
		}
	}

	// Handle risk ID update if present
	if riskIDStr, ok := updateData["riskId"].(string); ok && riskIDStr != "" {
		riskID, err := primitive.ObjectIDFromHex(riskIDStr)
		if err == nil {
			updateData["riskId"] = riskID
			log.Printf("[DEBUG] UpdateAction: Updated risk ID: %s", riskIDStr)
		} else {
			log.Printf("[WARN] UpdateAction: Invalid risk ID in update: %s", riskIDStr)
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
		log.Printf("[ERROR] UpdateAction: Error updating action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update action")
		return
	}

	if result.MatchedCount == 0 {
		log.Printf("[ERROR] UpdateAction: Action not found: %s", actionIDStr)
		utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		return
	}

	log.Printf("[DEBUG] UpdateAction: Updated %d document(s)", result.ModifiedCount)

	// Get the updated action
	var updatedAction models.Action
	err = actionCollection.FindOne(ctx, bson.M{"_id": actionID}).Decode(&updatedAction)
	if err != nil {
		log.Printf("[ERROR] UpdateAction: Error finding updated action: %v", err)
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
			Details:        updateData,
			CreatedAt:      time.Now(),
			IPAddress:      r.RemoteAddr,
			UserAgent:      r.UserAgent(),
		}
		
		// Save audit log to database
		go saveAuditLog(&auditLog)
		
		// Broadcast via WebSocket
		BroadcastAudit(&auditLog)
	}

	log.Printf("[SUCCESS] UpdateAction: Updated action %s", actionIDStr)
	utils.RespondWithJSON(w, http.StatusOK, updatedAction)
}

// DeleteAction deletes an action
func DeleteAction(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		log.Printf("[ERROR] DeleteAction: No organization ID in context")
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		log.Printf("[ERROR] DeleteAction: Invalid org ID format: %s", orgIDHex)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	// Get action ID from URL path
	vars := mux.Vars(r)
	actionIDStr := vars["id"]
	if actionIDStr == "" {
		log.Printf("[ERROR] DeleteAction: Missing action ID")
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	actionID, err := primitive.ObjectIDFromHex(actionIDStr)
	if err != nil {
		log.Printf("[ERROR] DeleteAction: Invalid action ID format: %s", actionIDStr)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID format")
		return
	}

	log.Printf("[DEBUG] DeleteAction: Deleting action: %s", actionIDStr)

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
			log.Printf("[ERROR] DeleteAction: Action not found: %s", actionIDStr)
			utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		} else {
			log.Printf("[ERROR] DeleteAction: Find error: %v", err)
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
		log.Printf("[ERROR] DeleteAction: Error deleting action: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete action")
		return
	}

	if result.DeletedCount == 0 {
		log.Printf("[ERROR] DeleteAction: Action not found: %s", actionIDStr)
		utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		return
	}

	log.Printf("[DEBUG] DeleteAction: Deleted %d document(s)", result.DeletedCount)

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

	log.Printf("[SUCCESS] DeleteAction: Deleted action %s", actionIDStr)
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
		log.Printf("[ERROR] Failed to save audit log: %v", err)
	} else {
		log.Printf("[DEBUG] Audit log saved: %s", auditLog.Action)
	}
}
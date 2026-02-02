package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"riskmgt/models"
	"riskmgt/utils"
)

// ==== APPROVAL CRUD OPERATIONS ====

// ListApprovals gets all approvals for the organization
func ListApprovals(w http.ResponseWriter, r *http.Request) {
	// Check if collection is initialized
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	// Build filter based on query parameters
	filter := bson.M{"organizationId": orgID}
	
	// Apply filters
	query := r.URL.Query()
	
	// Status filter
	if status := query.Get("status"); status != "" && status != "all" {
		filter["status"] = status
	}
	
	// Type filter
	if approvalType := query.Get("type"); approvalType != "" && approvalType != "all" {
		filter["type"] = approvalType
	}
	
	// Submitted by filter
	if submittedBy := query.Get("submittedBy"); submittedBy != "" && submittedBy != "all" {
		filter["submittedBy"] = submittedBy
	}
	
	// Search filter
	if search := query.Get("search"); search != "" {
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": search, "$options": "i"}},
			{"type": bson.M{"$regex": search, "$options": "i"}},
			{"status": bson.M{"$regex": search, "$options": "i"}},
			{"description": bson.M{"$regex": search, "$options": "i"}},
		}
	}
	
	// Time range filter
	if timeRange := query.Get("timeRange"); timeRange != "" {
		startDate := calculateApprovalStartDate(timeRange) // Changed function name
		if !startDate.IsZero() {
			filter["createdAt"] = bson.M{"$gte": startDate}
		}
	}

	// Pagination
	limit := 50
	skip := 0
	
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}
	
	if skipStr := query.Get("skip"); skipStr != "" {
		if s, err := strconv.Atoi(skipStr); err == nil && s >= 0 {
			skip = s
		}
	}

	opts := options.Find().
		SetSort(bson.D{{"submittedAt", -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cursor, err := approvalCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("ListApprovals - Find failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch approvals")
		return
	}
	defer cursor.Close(ctx)

	var approvals []bson.M
	if err = cursor.All(ctx, &approvals); err != nil {
		log.Printf("ListApprovals - cursor.All failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode approvals")
		return
	}

	if approvals == nil {
		approvals = []bson.M{}
	}

	// Get total count for pagination
	totalCount, _ := approvalCollection.CountDocuments(ctx, filter)

	log.Printf("✅ ListApprovals → returned %d approvals for org %s", len(approvals), orgIDStr)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"approvals": approvals,
		"total":     totalCount,
		"limit":     limit,
		"skip":      skip,
		"success":   true,
	})
}

// CreateApproval creates a new approval request
func CreateApproval(w http.ResponseWriter, r *http.Request) {
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "User ID required")
		return
	}

	// Parse request
	var req struct {
		Title           string                 `json:"title"`
		Type            string                 `json:"type"`
		Description     string                 `json:"description,omitempty"`
		EntityType      string                 `json:"entityType,omitempty"`
		EntityID        string                 `json:"entityId,omitempty"`
		RiskID          string                 `json:"riskId,omitempty"`
		RiskTitle       string                 `json:"riskTitle,omitempty"`
		TotalLevels     int                    `json:"totalLevels,omitempty"`
		Approvers       []string               `json:"approvers,omitempty"`
		AdditionalData  map[string]interface{} `json:"additionalData,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload: "+err.Error())
		return
	}

	// Validate
	if req.Title == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Title is required")
		return
	}
	if req.Type == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Type is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Create approval document
	approval := bson.M{
		"_id":             primitive.NewObjectID(),
		"organizationId":  orgID,
		"title":           req.Title,
		"type":            req.Type,
		"description":     req.Description,
		"entityType":      req.EntityType,
		"entityId":        req.EntityID,
		"riskId":          req.RiskID,
		"riskTitle":       req.RiskTitle,
		"status":          "pending",
		"submittedBy":     userIDStr,
		"submittedAt":     time.Now().UTC(),
		"currentLevel":    1,
		"totalLevels":     req.TotalLevels,
		"approvers":       req.Approvers,
		"additionalData":  req.AdditionalData,
		"createdAt":       time.Now().UTC(),
		"updatedAt":       time.Now().UTC(),
	}

	if req.TotalLevels == 0 {
		approval["totalLevels"] = 1
	}

	// If approvers not specified, set default based on type
	if len(req.Approvers) == 0 {
		approval["approvers"] = getDefaultApprovers(req.Type, orgIDStr)
	}

	// Add submitted user info
	userEmail, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)
	approval["submittedByEmail"] = userEmail
	approval["submittedByRole"] = userRole

	_, err = approvalCollection.InsertOne(ctx, approval)
	if err != nil {
		log.Printf("CreateApproval - insert error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create approval")
		return
	}

	// Create audit log
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		UserEmail:      userEmail,
		UserRole:       userRole,
		Action:         "approval_create",
		EntityType:     "approval",
		EntityID:       approval["_id"].(primitive.ObjectID),
		Details: bson.M{
			"title":    req.Title,
			"type":     req.Type,
			"status":   "pending",
			"entityId": req.EntityID,
		},
		CreatedAt: time.Now().UTC(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	
	if auditLogCollection != nil {
		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log: %v", err)
		}
		BroadcastAudit(&audit)
	}
	
	log.Printf("✅ Created approval %s: %s", approval["_id"].(primitive.ObjectID).Hex(), req.Title)
	
	utils.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"approval": approval,
		"message":  "Approval created successfully",
		"success":  true,
	})
}

// GetApproval gets a specific approval by ID
func GetApproval(w http.ResponseWriter, r *http.Request) {
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID format")
		return
	}

	vars := mux.Vars(r)
	approvalIDStr := vars["id"]
	if approvalIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Approval ID required")
		return
	}

	approvalID, err := primitive.ObjectIDFromHex(approvalIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid approval ID format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var approval bson.M
	err = approvalCollection.FindOne(ctx, bson.M{
		"_id":            approvalID,
		"organizationId": orgID,
	}).Decode(&approval)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Approval not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch approval")
		}
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, approval)
}

// UpdateApprovalStatus updates an approval's status (approve/reject)
func UpdateApprovalStatus(w http.ResponseWriter, r *http.Request) {
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	vars := mux.Vars(r)
	approvalIDStr := vars["id"]
	if approvalIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Approval ID required")
		return
	}

	approvalID, err := primitive.ObjectIDFromHex(approvalIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid approval ID format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "User ID required")
		return
	}

	var req struct {
		Status      string `json:"status"` // "approved", "rejected", "cancelled"
		Comment     string `json:"comment,omitempty"`
		NextLevel   int    `json:"nextLevel,omitempty"`
		ActionTaken string `json:"actionTaken,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}

	// Validate status
	validStatuses := []string{"pending", "approved", "rejected", "cancelled"}
	valid := false
	for _, s := range validStatuses {
		if s == req.Status {
			valid = true
			break
		}
	}
	if !valid {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid status")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get current approval
	var currentApproval bson.M
	err = approvalCollection.FindOne(ctx, bson.M{"_id": approvalID, "organizationId": orgID}).Decode(&currentApproval)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Approval not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch approval")
		}
		return
	}

	// Check if user can approve/reject
	if !canUserApprove(currentApproval, userIDStr, r.Context().Value("userRole").(string)) {
		utils.RespondWithError(w, http.StatusForbidden, "You don't have permission to update this approval")
		return
	}

	// Prepare update
	update := bson.M{
		"status":     req.Status,
		"updatedAt":  time.Now().UTC(),
	}

	// Add approval/rejection details
	now := time.Now().UTC()
	userEmail, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)
	
	if req.Status == "approved" || req.Status == "rejected" {
		update["processedBy"] = userIDStr
		update["processedByEmail"] = userEmail
		update["processedByRole"] = userRole
		update["processedAt"] = &now
		update["comment"] = req.Comment
		update["actionTaken"] = req.ActionTaken
		
		// If multi-level approval, update level
		if req.NextLevel > 0 && req.Status == "approved" {
			currentLevel, _ := currentApproval["currentLevel"].(int32)
			totalLevels, _ := currentApproval["totalLevels"].(int32)
			
			if int32(req.NextLevel) <= totalLevels {
				update["currentLevel"] = req.NextLevel
				update["status"] = "pending" // Still pending for next level
				
				// Add to approval history
				historyEntry := bson.M{
					"level":       currentLevel,
					"approvedBy":  userIDStr,
					"approvedAt":  now,
					"comment":     req.Comment,
					"actionTaken": req.ActionTaken,
				}
				
				// Initialize history array if needed
				history, ok := currentApproval["history"].([]bson.M)
				if !ok {
					history = []bson.M{}
				}
				history = append(history, historyEntry)
				update["history"] = history
			}
		}
	}

	result, err := approvalCollection.UpdateOne(ctx,
		bson.M{"_id": approvalID, "organizationId": orgID, "status": "pending"},
		bson.M{"$set": update},
	)

	if err != nil {
		log.Printf("UpdateApprovalStatus - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to update approval")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, 
			"Approval not found, already processed, or you don't have permission")
		return
	}

	// Get updated approval
	var updatedApproval bson.M
	err = approvalCollection.FindOne(ctx, bson.M{"_id": approvalID}).Decode(&updatedApproval)
	if err != nil {
		log.Printf("UpdateApprovalStatus - find updated error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Approval updated but failed to fetch details")
		return
	}

	// Create audit log
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		UserEmail:      userEmail,
		UserRole:       userRole,
		Action:         "approval_" + req.Status,
		EntityType:     "approval",
		EntityID:       approvalID,
		Details: bson.M{
			"title":    currentApproval["title"],
			"oldStatus": currentApproval["status"],
			"newStatus": req.Status,
			"comment":   req.Comment,
			"level":    currentApproval["currentLevel"],
		},
		CreatedAt: time.Now().UTC(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	
	if auditLogCollection != nil {
		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log: %v", err)
		}
		BroadcastAudit(&audit)
	}

	// If this was a risk submission approval, update the risk status
	if currentApproval["type"] == "risk_submission" && req.Status == "approved" {
		riskIDStr, ok := currentApproval["riskId"].(string)
		if ok && riskIDStr != "" {
			riskID, err := primitive.ObjectIDFromHex(riskIDStr)
			if err == nil {
				// Update the risk status to "active"
				_, _ = riskCollection.UpdateOne(ctx,
					bson.M{"_id": riskID, "organizationId": orgID},
					bson.M{"$set": bson.M{
						"status":    "active",
						"updatedAt": time.Now().UTC(),
					}},
				)
			}
		}
	}

	log.Printf("✅ Approval %s updated to %s by %s", approvalIDStr, req.Status, userIDStr)
	
	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":  "Approval " + req.Status + " successfully",
		"approval": updatedApproval,
		"success":  true,
	})
}

// DeleteApproval deletes an approval
func DeleteApproval(w http.ResponseWriter, r *http.Request) {
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	vars := mux.Vars(r)
	approvalIDStr := vars["id"]
	if approvalIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Approval ID required")
		return
	}

	approvalID, err := primitive.ObjectIDFromHex(approvalIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid approval ID format")
		return
	}

	// Only superadmin can delete approvals
	userRole, ok := r.Context().Value("userRole").(string)
	if !ok || userRole != "superadmin" {
		utils.RespondWithError(w, http.StatusForbidden, "Only superadmin can delete approvals")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get approval details for audit log
	var approval bson.M
	err = approvalCollection.FindOne(ctx, bson.M{
		"_id":            approvalID,
		"organizationId": orgID,
	}).Decode(&approval)
	
	if err != nil && err != mongo.ErrNoDocuments {
		log.Printf("DeleteApproval - find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch approval")
		return
	}

	result, err := approvalCollection.DeleteOne(ctx, bson.M{
		"_id":            approvalID,
		"organizationId": orgID,
	})

	if err != nil {
		log.Printf("DeleteApproval - delete error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to delete approval")
		return
	}

	if result.DeletedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "Approval not found")
		return
	}

	// Create audit log
	userIDStr, _ := r.Context().Value("userID").(string)
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	userEmail, _ := r.Context().Value("userName").(string)
	
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		UserEmail:      userEmail,
		UserRole:       userRole,
		Action:         "approval_delete",
		EntityType:     "approval",
		EntityID:       approvalID,
		Details: bson.M{
			"title":  approval["title"],
			"type":   approval["type"],
			"status": approval["status"],
		},
		CreatedAt: time.Now().UTC(),
		IPAddress: r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	
	if auditLogCollection != nil {
		if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
			log.Printf("Failed to create audit log: %v", err)
		}
		BroadcastAudit(&audit)
	}

	log.Printf("✅ Approval %s deleted by %s", approvalIDStr, userIDStr)
	
	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":    "Approval deleted successfully",
		"approvalId": approvalID.Hex(),
		"success":    true,
	})
}

// GetApprovalsByType gets approvals filtered by type
func GetApprovalsByType(w http.ResponseWriter, r *http.Request) {
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID format")
		return
	}

	vars := mux.Vars(r)
	approvalType := vars["type"]
	if approvalType == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Approval type required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	filter := bson.M{
		"organizationId": orgID,
		"type":           approvalType,
	}

	// Apply status filter if provided
	if status := r.URL.Query().Get("status"); status != "" && status != "all" {
		filter["status"] = status
	}

	opts := options.Find().SetSort(bson.D{{"submittedAt", -1}}).SetLimit(100)

	cursor, err := approvalCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("GetApprovalsByType - Find failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch approvals")
		return
	}
	defer cursor.Close(ctx)

	var approvals []bson.M
	if err = cursor.All(ctx, &approvals); err != nil {
		log.Printf("GetApprovalsByType - cursor.All failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode approvals")
		return
	}

	if approvals == nil {
		approvals = []bson.M{}
	}

	log.Printf("✅ GetApprovalsByType → returned %d %s approvals for org %s", 
		len(approvals), approvalType, orgIDStr)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"approvals": approvals,
		"type":      approvalType,
		"count":     len(approvals),
		"success":   true,
	})
}

// GetApprovalStats gets statistics for approvals
func GetApprovalStats(w http.ResponseWriter, r *http.Request) {
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Build aggregation pipeline for stats
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{
			{"organizationId", orgID},
		}}},
		{{"$facet", bson.D{
			{"byStatus", []bson.D{
				{{"$group", bson.D{
					{"_id", "$status"},
					{"count", bson.D{{"$sum", 1}}},
				}}},
			}},
			{"byType", []bson.D{
				{{"$group", bson.D{
					{"_id", "$type"},
					{"count", bson.D{{"$sum", 1}}},
				}}},
			}},
			{"pendingByType", []bson.D{
				{{"$match", bson.D{{"status", "pending"}}}},
				{{"$group", bson.D{
					{"_id", "$type"},
					{"count", bson.D{{"$sum", 1}}},
				}}},
			}},
			{"recentActivity", []bson.D{
				{{"$sort", bson.D{{"submittedAt", -1}}}},
				{{"$limit", 10}},
			}},
			{"averageProcessingTime", []bson.D{
				{{"$match", bson.D{
					{"status", bson.D{{"$in", []string{"approved", "rejected"}}}},
					{"submittedAt", bson.D{{"$exists", true}}},
					{"processedAt", bson.D{{"$exists", true}}},
				}}},
				{{"$project", bson.D{
					{"processingTime", bson.D{{"$subtract", []interface{}{"$processedAt", "$submittedAt"}}}},
				}}},
				{{"$group", bson.D{
					{"_id", nil},
					{"avgTime", bson.D{{"$avg", "$processingTime"}}},
					{"minTime", bson.D{{"$min", "$processingTime"}}},
					{"maxTime", bson.D{{"$max", "$processingTime"}}},
				}}},
			}},
		}}},
	}

	cursor, err := approvalCollection.Aggregate(ctx, pipeline)
	if err != nil {
		log.Printf("GetApprovalStats - aggregate failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to calculate statistics")
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		log.Printf("GetApprovalStats - cursor.All failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode statistics")
		return
	}

	// Process results
	stats := map[string]interface{}{
		"byStatus":               map[string]int{},
		"byType":                 map[string]int{},
		"pendingByType":          map[string]int{},
		"recentActivity":         []bson.M{},
		"averageProcessingTime":  int64(0),
		"minProcessingTime":      int64(0),
		"maxProcessingTime":      int64(0),
	}

	if len(results) > 0 {
		result := results[0]
		
		// Process byStatus
		if byStatus, ok := result["byStatus"].(bson.A); ok {
			for _, item := range byStatus {
				if m, ok := item.(bson.M); ok {
					if status, ok := m["_id"].(string); ok {
						if count, ok := m["count"].(int32); ok {
							stats["byStatus"].(map[string]int)[status] = int(count)
						}
					}
				}
			}
		}
		
		// Process byType
		if byType, ok := result["byType"].(bson.A); ok {
			for _, item := range byType {
				if m, ok := item.(bson.M); ok {
					if typeVal, ok := m["_id"].(string); ok {
						if count, ok := m["count"].(int32); ok {
							stats["byType"].(map[string]int)[typeVal] = int(count)
						}
					}
				}
			}
		}
		
		// Process pendingByType
		if pendingByType, ok := result["pendingByType"].(bson.A); ok {
			for _, item := range pendingByType {
				if m, ok := item.(bson.M); ok {
					if typeVal, ok := m["_id"].(string); ok {
						if count, ok := m["count"].(int32); ok {
							stats["pendingByType"].(map[string]int)[typeVal] = int(count)
						}
					}
				}
			}
		}
		
		// Process recentActivity
		if recentActivity, ok := result["recentActivity"].(bson.A); ok {
			stats["recentActivity"] = recentActivity
		}
		
		// Process averageProcessingTime
		if avgTime, ok := result["averageProcessingTime"].(bson.A); ok && len(avgTime) > 0 {
			if m, ok := avgTime[0].(bson.M); ok {
				if avg, ok := m["avgTime"].(int64); ok {
					stats["averageProcessingTime"] = avg / int64(time.Millisecond) // Convert to milliseconds
				}
				if min, ok := m["minTime"].(int64); ok {
					stats["minProcessingTime"] = min / int64(time.Millisecond)
				}
				if max, ok := m["maxTime"].(int64); ok {
					stats["maxProcessingTime"] = max / int64(time.Millisecond)
				}
			}
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"stats":    stats,
		"success":  true,
	})
}

// ==== HELPER FUNCTIONS ====

// Helper to check if user can approve
func canUserApprove(approval bson.M, userID string, userRole string) bool {
	// Superadmin can approve anything
	if userRole == "superadmin" {
		return true
	}
	
	// Admin can approve most things
	if userRole == "admin" {
		approvalType, _ := approval["type"].(string)
		// Admin cannot approve admin user creation
		if approvalType == "user_create_admin" {
			return false
		}
		return true
	}
	
	// Regular users can only approve if they're in the approvers list
	approvers, _ := approval["approvers"].([]string)
	
	// Check if user is in approvers list
	for _, approver := range approvers {
		if approver == userID {
			return true
		}
	}
	
	return false
}

// Helper to get default approvers based on approval type
func getDefaultApprovers(approvalType string, orgID string) []string {
	// Default approvers logic
	// This is a simplified version - you might want to implement more sophisticated logic
	
	switch approvalType {
	case "risk_submission":
		// For risk submissions, default to admins and risk managers
		return []string{} // Empty means use role-based approval
	case "user_create_admin":
		// Only superadmin can approve admin user creation
		return []string{"superadmin"}
	case "user_create":
		// Admin can approve regular user creation
		return []string{"admin"}
	case "policy_change":
		// Multiple approvers for policy changes
		return []string{"admin", "superadmin"}
	default:
		// Default to admin approval
		return []string{"admin"}
	}
}

// Helper function to calculate start date based on time range string
// Renamed to avoid conflict with audit_handler.go
func calculateApprovalStartDate(timeRange string) time.Time {
	now := time.Now().UTC()
	
	switch timeRange {
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	case "yesterday":
		yesterday := now.AddDate(0, 0, -1)
		return time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, time.UTC)
	case "thisWeek":
		weekday := now.Weekday()
		daysSinceMonday := (weekday - time.Monday + 7) % 7
		startOfWeek := now.AddDate(0, 0, -int(daysSinceMonday))
		return time.Date(startOfWeek.Year(), startOfWeek.Month(), startOfWeek.Day(), 0, 0, 0, 0, time.UTC)
	case "thisMonth":
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	case "lastMonth":
		lastMonth := now.AddDate(0, -1, 0)
		return time.Date(lastMonth.Year(), lastMonth.Month(), 1, 0, 0, 0, 0, time.UTC)
	case "last30days":
		return now.AddDate(0, 0, -30)
	case "last90days":
		return now.AddDate(0, 0, -90)
	default:
		return time.Time{} // Zero time for "all"
	}
}
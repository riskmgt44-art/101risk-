// handlers/approval_handler.go
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
	"go.mongodb.org/mongo-driver/mongo/options"

	"riskmgt/utils"
)

// GetAnalystApprovals gets approvals submitted by the current analyst
func GetAnalystApprovals(w http.ResponseWriter, r *http.Request) {
	// Check if collection is initialized - CRITICAL FIX
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil. Call handlers.InitializeCollections() in main.go!")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()

	// Filter for approvals submitted by this analyst
	filter := bson.M{
		"organizationId": orgID,
		"submittedBy":    userIDStr,
	}

	opts := options.Find().
		SetSort(bson.D{{"submittedAt", -1}})

	cursor, err := approvalCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("GetAnalystApprovals - Find failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch approvals")
		return
	}
	defer cursor.Close(ctx)

	var approvals []bson.M
	if err = cursor.All(ctx, &approvals); err != nil {
		log.Printf("GetAnalystApprovals - cursor.All failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode approvals")
		return
	}

	if approvals == nil {
		approvals = []bson.M{}
	}

	log.Printf("✅ GetAnalystApprovals → returned %d records for analyst %s", 
		len(approvals), userIDStr)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"approvals": approvals,
		"count":     len(approvals),
		"success":   true,
	})
}

// GetAnalystApprovalStats gets statistics for analyst's approvals
func GetAnalystApprovalStats(w http.ResponseWriter, r *http.Request) {
	// Check if collection is initialized
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil. Call handlers.InitializeCollections() in main.go!")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Build aggregation pipeline for stats
	pipeline := mongo.Pipeline{
		{{"$match", bson.D{
			{"organizationId", orgID},
			{"submittedBy", userIDStr},
		}}},
		{{"$group", bson.D{
			{"_id", nil},
			{"totalApprovals", bson.D{{"$sum", 1}}},
			{"pendingApprovals", bson.D{{
				"$sum", bson.D{{
					"$cond", bson.A{bson.D{{"$eq", bson.A{"$status", "pending"}}}, 1, 0},
				}},
			}}},
			{"approvedSubmissions", bson.D{{
				"$sum", bson.D{{
					"$cond", bson.A{bson.D{{"$eq", bson.A{"$status", "approved"}}}, 1, 0},
				}},
			}}},
			{"rejectedSubmissions", bson.D{{
				"$sum", bson.D{{
					"$cond", bson.A{bson.D{{"$eq", bson.A{"$status", "rejected"}}}, 1, 0},
				}},
			}}},
			{"cancelledSubmissions", bson.D{{
				"$sum", bson.D{{
					"$cond", bson.A{bson.D{{"$eq", bson.A{"$status", "cancelled"}}}, 1, 0},
				}},
			}}},
		}}},
	}

	cursor, err := approvalCollection.Aggregate(ctx, pipeline)
	if err != nil {
		log.Printf("GetAnalystApprovalStats - aggregate failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to calculate statistics")
		return
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err = cursor.All(ctx, &results); err != nil {
		log.Printf("GetAnalystApprovalStats - cursor.All failed: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode statistics")
		return
	}

	stats := map[string]interface{}{
		"totalApprovals":       0,
		"pendingApprovals":     0,
		"approvedSubmissions":  0,
		"rejectedSubmissions":  0,
		"cancelledSubmissions": 0,
	}

	if len(results) > 0 {
		result := results[0]
		if val, ok := result["totalApprovals"]; ok {
			stats["totalApprovals"] = val
		}
		if val, ok := result["pendingApprovals"]; ok {
			stats["pendingApprovals"] = val
		}
		if val, ok := result["approvedSubmissions"]; ok {
			stats["approvedSubmissions"] = val
		}
		if val, ok := result["rejectedSubmissions"]; ok {
			stats["rejectedSubmissions"] = val
		}
		if val, ok := result["cancelledSubmissions"]; ok {
			stats["cancelledSubmissions"] = val
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"stats":    stats,
		"success":  true,
	})
}

// AnalystCancelApproval allows an analyst to cancel their own approval request
func AnalystCancelApproval(w http.ResponseWriter, r *http.Request) {
	// Check if collection is initialized
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil. Call handlers.InitializeCollections() in main.go!")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	vars := mux.Vars(r)
	approvalIDStr := vars["id"]
	if approvalIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "approval id required")
		return
	}

	approvalID, err := primitive.ObjectIDFromHex(approvalIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid approval id format")
		return
	}

	// Parse request body for cancellation reason
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Update approval - only if submitted by this analyst and status is pending
	filter := bson.M{
		"_id":            approvalID,
		"organizationId": orgID,
		"submittedBy":    userIDStr,
		"status":         "pending",
	}

	update := bson.M{
		"$set": bson.M{
			"status":             "cancelled",
			"cancelledAt":        time.Now().UTC(),
			"cancelledBy":        userIDStr,
			"cancellationReason": req.Reason,
			"updatedAt":          time.Now().UTC(),
		},
	}

	result, err := approvalCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.Printf("AnalystCancelApproval - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to cancel approval")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, 
			"approval not found, already processed, or you don't have permission to cancel it")
		return
	}

	// Get updated approval
	var updatedApproval bson.M
	err = approvalCollection.FindOne(ctx, bson.M{"_id": approvalID}).Decode(&updatedApproval)
	if err != nil {
		log.Printf("AnalystCancelApproval - find updated error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "approval cancelled but failed to fetch details")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":  "Approval cancelled successfully",
		"approval": updatedApproval,
		"success":  true,
	})
}

// GetAnalystApproval gets a specific approval for the analyst
func GetAnalystApproval(w http.ResponseWriter, r *http.Request) {
	// Check if collection is initialized
	if approvalCollection == nil {
		log.Println("❌ FATAL: approvalCollection is nil. Call handlers.InitializeCollections() in main.go!")
		utils.RespondWithError(w, http.StatusInternalServerError, 
			"Server configuration error: approvals database not initialized")
		return
	}

	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id format")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	vars := mux.Vars(r)
	approvalIDStr := vars["id"]
	if approvalIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "approval id required")
		return
	}

	approvalID, err := primitive.ObjectIDFromHex(approvalIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid approval id format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Find approval that belongs to this analyst
	filter := bson.M{
		"_id":            approvalID,
		"organizationId": orgID,
		"submittedBy":    userIDStr,
	}

	var approval bson.M
	err = approvalCollection.FindOne(ctx, filter).Decode(&approval)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "approval not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch approval")
		}
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"approval": approval,
		"success":  true,
	})
}
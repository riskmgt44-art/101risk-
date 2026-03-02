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

	"riskmgt/models"
	"riskmgt/utils"
)

// ListAssets returns assets based on user's permissions
func ListAssets(w http.ResponseWriter, r *http.Request) {
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

	// Get user context for permission filtering
	userIDStr, _ := r.Context().Value("userID").(string)
	userRole, _ := r.Context().Value("userRole").(string)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Build base filter
	filter := bson.M{"organizationId": orgID, "status": bson.M{"$ne": "inactive"}}

	// For non-superadmin roles, filter by assigned/owned assets
	if (userRole == "admin" || userRole == "risk_manager" || userRole == "user") && userIDStr != "" {
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid user id")
			return
		}

		assignedAssetIDs := getUserAssignedAssetIDs(ctx, userID, orgID, userRole)

		if len(assignedAssetIDs) > 0 {
			filter["_id"] = bson.M{"$in": assignedAssetIDs}
		} else {
			// If no assigned assets, return empty list for non-superadmin
			utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
			return
		}
	}

	opts := options.Find().SetSort(bson.D{{"createdAt", -1}})

	cursor, err := assetCollection.Find(ctx, filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
			return
		}
		log.Printf("assets Find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer cursor.Close(ctx)

	var assets []models.Asset
	if err = cursor.All(ctx, &assets); err != nil {
		log.Printf("cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode assets")
		return
	}

	if assets == nil {
		assets = []models.Asset{}
	}

	log.Printf("returned %d assets for org %s, user role: %s", len(assets), orgIDStr, userRole)
	utils.RespondWithJSON(w, http.StatusOK, assets)
}

// GetMyAssets - Alternative endpoint for users to get their assigned assets
func GetMyAssets(w http.ResponseWriter, r *http.Request) {
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

	// Get user context
	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	userRole, _ := r.Context().Value("userRole").(string)
	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get user's assigned asset IDs
	assignedAssetIDs := getUserAssignedAssetIDs(ctx, userID, orgID, userRole)

	if len(assignedAssetIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
		return
	}

	// Fetch the actual asset documents
	filter := bson.M{
		"_id":            bson.M{"$in": assignedAssetIDs},
		"organizationId": orgID,
		"status":         "active",
	}

	opts := options.Find().SetSort(bson.D{{"name", 1}})

	cursor, err := assetCollection.Find(ctx, filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
			return
		}
		log.Printf("my assets Find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer cursor.Close(ctx)

	var assets []models.Asset
	if err = cursor.All(ctx, &assets); err != nil {
		log.Printf("cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode assets")
		return
	}

	if assets == nil {
		assets = []models.Asset{}
	}

	log.Printf("returned %d assigned assets for user %s, role: %s", len(assets), userIDStr, userRole)
	utils.RespondWithJSON(w, http.StatusOK, assets)
}

type CreateAssetRequest struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Nature      string `json:"nature,omitempty"`
	Location    string `json:"location,omitempty"`
	OwnerUserId string `json:"ownerUserId,omitempty"`
	Description string `json:"description,omitempty"`
}

func CreateAsset(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	role, ok := r.Context().Value("userRole").(string)
	if !ok || (role != "superadmin" && role != "admin" && role != "risk_manager") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to create asset")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req CreateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if req.Name == "" || req.Category == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "missing required fields: name and category")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check unique name within org
	count, err := assetCollection.CountDocuments(ctx, bson.M{"organizationId": orgID, "name": req.Name})
	if err != nil {
		log.Printf("unique check error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	if count > 0 {
		utils.RespondWithError(w, http.StatusConflict, "asset name must be unique within organization")
		return
	}

	// Initialize asset with basic fields
	asset := models.Asset{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		Name:           req.Name,
		Category:       req.Category,
		Nature:         req.Nature,
		Location:       req.Location,
		Description:    req.Description,
		CreatedBy:      userID,
		CreatedAt:      time.Now().UTC(),
		Status:         "active",
		AssignedUserIDs: []primitive.ObjectID{},
	}

	// Handle owner assignment if OwnerUserId is provided
	if req.OwnerUserId != "" {
		ownerID, err := primitive.ObjectIDFromHex(req.OwnerUserId)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid owner user id format")
			return
		}

		// Verify the owner user exists in the organization
		var ownerUser models.User
		err = userCollection.FindOne(ctx, bson.M{
			"_id":            ownerID,
			"organizationId": orgID,
			"deletedAt":      nil,
		}).Decode(&ownerUser)
		
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.RespondWithError(w, http.StatusBadRequest, "owner user not found in organization")
				return
			}
			log.Printf("owner user fetch error: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to verify owner user")
			return
		}

		// Set owner fields
		asset.OwnerUserID = &ownerID
		asset.Owner = ownerUser.FirstName + " " + ownerUser.LastName
		
		// Also add owner to assigned users
		asset.AssignedUserIDs = append(asset.AssignedUserIDs, ownerID)
	}

	_, err = assetCollection.InsertOne(ctx, asset)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			utils.RespondWithError(w, http.StatusConflict, "asset with this name already exists")
			return
		}
		log.Printf("insert error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to create asset")
		return
	}

	// Audit
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "asset_create",
		EntityType:     "asset",
		EntityID:       asset.ID,
		Details: bson.M{
			"name":      req.Name,
			"category":  req.Category,
			"owner":     req.OwnerUserId,
			"ownerName": asset.Owner,
		},
		CreatedAt: time.Now().UTC(),
	}
	_, _ = auditLogCollection.InsertOne(ctx, audit)
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusCreated, asset)
}

func GetAsset(w http.ResponseWriter, r *http.Request) {
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

	// Get user context for permission check
	userIDStr, _ := r.Context().Value("userID").(string)
	userRole, _ := r.Context().Value("userRole").(string)

	// Get asset ID from URL path parameter
	vars := mux.Vars(r)
	assetIDStr := vars["id"]
	if assetIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "asset id required")
		return
	}

	assetID, err := primitive.ObjectIDFromHex(assetIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check permission for non-superadmin users
	if (userRole == "admin" || userRole == "risk_manager" || userRole == "user") && userIDStr != "" {
		userID, _ := primitive.ObjectIDFromHex(userIDStr)
		if !canUserAccessAsset(ctx, userID, orgID, assetID, userRole) {
			utils.RespondWithError(w, http.StatusForbidden, "access denied to this asset")
			return
		}
	}

	var asset models.Asset
	err = assetCollection.FindOne(ctx, bson.M{"_id": assetID, "organizationId": orgID}).Decode(&asset)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "asset not found")
			return
		}
		log.Printf("find asset error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, asset)
}

type UpdateAssetRequest struct {
	Name        string `json:"name,omitempty"`
	Category    string `json:"category,omitempty"`
	Nature      string `json:"nature,omitempty"`
	Location    string `json:"location,omitempty"`
	Owner       string `json:"owner,omitempty"`
	OwnerUserId string `json:"ownerUserId,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
}

func UpdateAsset(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	role, ok := r.Context().Value("userRole").(string)
	if !ok || (role != "superadmin" && role != "admin" && role != "risk_manager") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to update asset")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	// Get asset ID from URL path parameter
	vars := mux.Vars(r)
	assetIDStr := vars["id"]
	if assetIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "asset id required")
		return
	}

	assetID, err := primitive.ObjectIDFromHex(assetIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id format")
		return
	}

	// Check permission for non-superadmin users
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if (role == "admin" || role == "risk_manager") && !canUserAccessAsset(ctx, userID, orgID, assetID, role) {
		utils.RespondWithError(w, http.StatusForbidden, "access denied to update this asset")
		return
	}

	var req UpdateAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	update := bson.M{}
	if req.Name != "" {
		update["name"] = req.Name
	}
	if req.Category != "" {
		update["category"] = req.Category
	}
	if req.Nature != "" {
		update["nature"] = req.Nature
	}
	if req.Location != "" {
		update["location"] = req.Location
	}
	if req.Description != "" {
		update["description"] = req.Description
	}
	if req.Status != "" {
		update["status"] = req.Status
	}
	update["updatedAt"] = time.Now().UTC()
	update["updatedBy"] = userID

	// Handle owner update if OwnerUserId is provided
	if req.OwnerUserId != "" {
		ownerID, err := primitive.ObjectIDFromHex(req.OwnerUserId)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid owner user id format")
			return
		}

		// Verify the owner user exists in the organization
		var ownerUser models.User
		err = userCollection.FindOne(ctx, bson.M{
			"_id":            ownerID,
			"organizationId": orgID,
			"deletedAt":      nil,
		}).Decode(&ownerUser)
		
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.RespondWithError(w, http.StatusBadRequest, "owner user not found in organization")
				return
			}
			log.Printf("owner user fetch error: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to verify owner user")
			return
		}

		// Set owner fields
		update["ownerUserId"] = ownerID
		update["owner"] = ownerUser.FirstName + " " + ownerUser.LastName
		
		// Also ensure owner is in assigned users
		update["$addToSet"] = bson.M{"assignedUserIds": ownerID}
	}

	if len(update) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	result, err := assetCollection.UpdateOne(ctx, bson.M{"_id": assetID, "organizationId": orgID}, bson.M{"$set": update})
	if err != nil {
		log.Printf("update asset error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}
	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "asset not found")
		return
	}

	// If name was updated, check for conflicts
	if req.Name != "" {
		// Check if new name conflicts with other assets
		count, err := assetCollection.CountDocuments(ctx, bson.M{
			"_id":            bson.M{"$ne": assetID},
			"organizationId": orgID,
			"name":           req.Name,
		})
		if err != nil {
			log.Printf("name conflict check error: %v", err)
		} else if count > 0 {
			utils.RespondWithError(w, http.StatusConflict, "asset name must be unique within organization")
			return
		}
	}

	// Audit
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "asset_update",
		EntityType:     "asset",
		EntityID:       assetID,
		Details:        update,
		CreatedAt:      time.Now().UTC(),
	}
	_, _ = auditLogCollection.InsertOne(ctx, audit)
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "asset updated successfully"})
}

func DeleteAsset(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	role, ok := r.Context().Value("userRole").(string)
	if !ok || (role != "superadmin" && role != "admin") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to delete asset")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id")
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	// Get asset ID from URL path parameter
	vars := mux.Vars(r)
	assetIDStr := vars["id"]
	if assetIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "asset id required")
		return
	}

	assetID, err := primitive.ObjectIDFromHex(assetIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id format")
		return
	}

	// Check permission for non-superadmin users
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if role == "admin" && !canUserAccessAsset(ctx, userID, orgID, assetID, role) {
		utils.RespondWithError(w, http.StatusForbidden, "access denied to delete this asset")
		return
	}

	// Check if linked to risks/actions
	riskCount, err := riskCollection.CountDocuments(ctx, bson.M{"assetId": assetID})
	if err != nil {
		log.Printf("check linked risks error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	actionCount, err := actionCollection.CountDocuments(ctx, bson.M{"assetId": assetID})
	if err != nil {
		log.Printf("check linked actions error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	if riskCount > 0 || actionCount > 0 {
		utils.RespondWithError(w, http.StatusConflict, "asset linked to risks or actions, cannot delete")
		return
	}

	update := bson.M{"status": "inactive", "deletedAt": time.Now().UTC(), "deletedBy": userID}

	result, err := assetCollection.UpdateOne(ctx, bson.M{"_id": assetID, "organizationId": orgID}, bson.M{"$set": update})
	if err != nil {
		log.Printf("delete asset error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to delete asset")
		return
	}
	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "asset not found")
		return
	}

	// Audit
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "asset_delete",
		EntityType:     "asset",
		EntityID:       assetID,
		Details:        bson.M{"status": "inactive"},
		CreatedAt:      time.Now().UTC(),
	}
	_, _ = auditLogCollection.InsertOne(ctx, audit)
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"message": "asset deactivated successfully"})
}

// GetAssetRisks - Get risks associated with an asset
func GetAssetRisks(w http.ResponseWriter, r *http.Request) {
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

	// Get user context for permission check
	userIDStr, _ := r.Context().Value("userID").(string)
	userRole, _ := r.Context().Value("userRole").(string)

	// Get asset ID from URL path parameter
	vars := mux.Vars(r)
	assetIDStr := vars["id"]
	if assetIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "asset id required")
		return
	}

	assetID, err := primitive.ObjectIDFromHex(assetIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check permission for non-superadmin users
	if (userRole == "admin" || userRole == "risk_manager" || userRole == "user") && userIDStr != "" {
		userID, _ := primitive.ObjectIDFromHex(userIDStr)
		if !canUserAccessAsset(ctx, userID, orgID, assetID, userRole) {
			utils.RespondWithError(w, http.StatusForbidden, "access denied to this asset")
			return
		}
	}

	filter := bson.M{"assetId": assetID, "organizationId": orgID}
	opts := options.Find().SetSort(bson.D{{"createdAt", -1}})

	cursor, err := riskCollection.Find(ctx, filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.Risk{})
			return
		}
		log.Printf("risks Find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}
	defer cursor.Close(ctx)

	var risks []models.Risk
	if err = cursor.All(ctx, &risks); err != nil {
		log.Printf("cursor decode error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode risks")
		return
	}

	if risks == nil {
		risks = []models.Risk{}
	}

	utils.RespondWithJSON(w, http.StatusOK, risks)
}

// Helper function to check if user can access an asset
func canUserAccessAsset(ctx context.Context, userID, orgID, assetID primitive.ObjectID, role string) bool {
	if role == "superadmin" || role == "super-admin" {
		return true
	}

	// Get user's assigned assets (using the same logic from GetAdminDashboard)
	assignedAssetIDs := getUserAssignedAssetIDs(ctx, userID, orgID, role)
	
	// Check if assetID is in assigned assets
	for _, id := range assignedAssetIDs {
		if id == assetID {
			return true
		}
	}
	
	return false
}

// AssignUsersToAsset assigns users to an asset
func AssignUsersToAsset(w http.ResponseWriter, r *http.Request) {
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

	// Get user context for permission check
	userIDStr, ok := r.Context().Value("userID").(string)
	if !ok || userIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "user id required")
		return
	}

	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	requestorRole, ok := r.Context().Value("userRole").(string)
	if !ok || (requestorRole != "superadmin" && requestorRole != "admin" && requestorRole != "risk_manager") {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	// Get asset ID from path
	vars := mux.Vars(r)
	assetIDStr := vars["id"]
	if assetIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "asset id required")
		return
	}

	assetID, err := primitive.ObjectIDFromHex(assetIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check permission for non-superadmin users
	if (requestorRole == "admin" || requestorRole == "risk_manager") && !canUserAccessAsset(ctx, userID, orgID, assetID, requestorRole) {
		utils.RespondWithError(w, http.StatusForbidden, "access denied to manage this asset")
		return
	}

	var req struct {
		UserIDs []string `json:"userIds"` // Array of user IDs to assign
		Action  string   `json:"action"`  // "assign" or "remove"
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if len(req.UserIDs) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "no user IDs provided")
		return
	}

	if req.Action != "assign" && req.Action != "remove" {
		utils.RespondWithError(w, http.StatusBadRequest, "action must be 'assign' or 'remove'")
		return
	}

	// Verify asset exists and belongs to org
	var asset models.Asset
	err = assetCollection.FindOne(ctx, bson.M{
		"_id":            assetID,
		"organizationId": orgID,
		"status":         "active",
	}).Decode(&asset)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "asset not found")
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch asset")
		return
	}

	// Convert user IDs to ObjectIDs
	var userObjectIDs []primitive.ObjectID
	for _, userIDStr := range req.UserIDs {
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid user id: "+userIDStr)
			return
		}
		userObjectIDs = append(userObjectIDs, userID)
	}

	// Verify users exist in organization
	filter := bson.M{
		"_id":            bson.M{"$in": userObjectIDs},
		"organizationId": orgID,
		"deletedAt":      nil,
	}

	count, err := userCollection.CountDocuments(ctx, filter)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to verify users")
		return
	}

	if int(count) != len(userObjectIDs) {
		utils.RespondWithError(w, http.StatusBadRequest, "one or more users not found in organization")
		return
	}

	// Get MongoDB client from collection
	client := userCollection.Database().Client()
	
	// Start a session for transaction-like behavior
	session, err := client.StartSession()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to start database session")
		return
	}
	defer session.EndSession(ctx)

	// Execute operations in a session
	_, err = session.WithTransaction(ctx, func(sessionContext mongo.SessionContext) (interface{}, error) {
		// Update asset assignment
		var update bson.M
		if req.Action == "assign" {
			// Add users to asset
			update = bson.M{
				"$addToSet": bson.M{"assignedUserIds": bson.M{"$each": userObjectIDs}},
				"$set":      bson.M{"updatedAt": time.Now().UTC()},
			}
		} else {
			// Remove users from asset
			update = bson.M{
				"$pull": bson.M{"assignedUserIds": bson.M{"$in": userObjectIDs}},
				"$set":  bson.M{"updatedAt": time.Now().UTC()},
			}
		}

		// Update asset
		result, err := assetCollection.UpdateOne(sessionContext,
			bson.M{"_id": assetID, "organizationId": orgID},
			update,
		)
		if err != nil {
			return nil, err
		}

		if result.MatchedCount == 0 {
			return nil, mongo.ErrNoDocuments
		}

		// Update users' asset assignments
		for _, userID := range userObjectIDs {
			var userUpdate bson.M
			if req.Action == "assign" {
				userUpdate = bson.M{
					"$addToSet": bson.M{"assetIds": assetID},
				}
			} else {
				userUpdate = bson.M{
					"$pull": bson.M{"assetIds": assetID},
				}
			}

			_, err := userCollection.UpdateOne(sessionContext,
				bson.M{"_id": userID, "organizationId": orgID},
				userUpdate,
			)
			if err != nil {
				log.Printf("Failed to update user %s asset assignments: %v", userID.Hex(), err)
				// Continue with other users
			}
		}

		return nil, nil
	})

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "asset not found")
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}

	// Create audit log
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "asset_user_" + req.Action,
		EntityType:     "asset",
		EntityID:       assetID,
		Details: bson.M{
			"assetName": asset.Name,
			"userIds":   req.UserIDs,
			"action":    req.Action,
		},
		CreatedAt: time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "users " + req.Action + "ed to asset successfully",
		"assetId": assetID.Hex(),
		"action":  req.Action,
		"userIds": req.UserIDs,
	})
}

// GetAssetUsers returns users assigned to an asset
func GetAssetUsers(w http.ResponseWriter, r *http.Request) {
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

	// Get user context for permission check
	userIDStr, _ := r.Context().Value("userID").(string)
	userRole, _ := r.Context().Value("userRole").(string)

	// Get asset ID from path
	vars := mux.Vars(r)
	assetIDStr := vars["id"]
	if assetIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "asset id required")
		return
	}

	assetID, err := primitive.ObjectIDFromHex(assetIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check permission for non-superadmin users
	if (userRole == "admin" || userRole == "risk_manager" || userRole == "user") && userIDStr != "" {
		userID, _ := primitive.ObjectIDFromHex(userIDStr)
		if !canUserAccessAsset(ctx, userID, orgID, assetID, userRole) {
			utils.RespondWithError(w, http.StatusForbidden, "access denied to this asset")
			return
		}
	}

	// Get asset to retrieve assigned user IDs
	var asset models.Asset
	err = assetCollection.FindOne(ctx, bson.M{
		"_id":            assetID,
		"organizationId": orgID,
		"status":         "active",
	}).Decode(&asset)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.User{})
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch asset")
		return
	}

	if len(asset.AssignedUserIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, []models.User{})
		return
	}

	// Get user details for assigned users
	cursor, err := userCollection.Find(ctx, bson.M{
		"_id":       bson.M{"$in": asset.AssignedUserIDs},
		"deletedAt": nil,
	}, options.Find().SetProjection(bson.M{
		"passwordHash": 0,
		"mfaSecret":    0,
		"resetToken":   0,
	}))
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.User{})
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch users")
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode users")
		return
	}

	if users == nil {
		users = []models.User{}
	}

	utils.RespondWithJSON(w, http.StatusOK, users)
}
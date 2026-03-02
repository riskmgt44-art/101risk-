package handlers

import (
	"context"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"riskmgt/models"
	"riskmgt/utils"
)

// GetUserAssignedAssets returns only assets assigned to the current user
func GetUserAssignedAssets(w http.ResponseWriter, r *http.Request) {
	// Extract user and org from context
	userIDHex, ok := r.Context().Value("userID").(string)
	orgIDHex, ok2 := r.Context().Value("orgID").(string)
	
	if !ok || !ok2 || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	
	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	
	// Get user to check role
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Super admin can see all assets
	if user.Role == "superadmin" || user.Role == "super-admin" {
		// Return all active assets
		filter := bson.M{"organizationId": orgID, "status": "active"}
		opts := options.Find().SetSort(bson.D{{"name", 1}})
		
		cursor, err := assetCollection.Find(ctx, filter, opts)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
				return
			}
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch assets")
			return
		}
		defer cursor.Close(ctx)
		
		var assets []models.Asset
		if err = cursor.All(ctx, &assets); err != nil {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode assets")
			return
		}
		
		if assets == nil {
			assets = []models.Asset{}
		}
		
		utils.RespondWithJSON(w, http.StatusOK, assets)
		return
	}
	
	// Get user's assigned asset IDs
	var assignedAssetIDs []primitive.ObjectID
	
	// Check if user has AssetIDs field populated
	if len(user.AssetIDs) > 0 {
		assignedAssetIDs = user.AssetIDs
	} else {
		// If no assigned assets, return empty array
		utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
		return
	}
	
	// Fetch the actual asset details
	filter := bson.M{
		"_id": bson.M{"$in": assignedAssetIDs},
		"organizationId": orgID,
		"status": "active",
	}
	
	opts := options.Find().SetSort(bson.D{{"name", 1}})
	
	cursor, err := assetCollection.Find(ctx, filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.Asset{})
			return
		}
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch assets")
		return
	}
	defer cursor.Close(ctx)
	
	var assets []models.Asset
	if err = cursor.All(ctx, &assets); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode assets")
		return
	}
	
	if assets == nil {
		assets = []models.Asset{}
	}
	
	utils.RespondWithJSON(w, http.StatusOK, assets)
}

// GetAvailableUsersForAssignment returns users available for asset assignment
func GetAvailableUsersForAssignment(w http.ResponseWriter, r *http.Request) {
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

	// Optional: Get asset ID to exclude already assigned users
	assetID := r.URL.Query().Get("assetId")
	var excludeUserIDs []primitive.ObjectID
	
	if assetID != "" {
		assetObjectID, err := primitive.ObjectIDFromHex(assetID)
		if err == nil {
			// Get asset's currently assigned users
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			
			var asset models.Asset
			err = assetCollection.FindOne(ctx, bson.M{
				"_id":            assetObjectID,
				"organizationId": orgID,
			}).Decode(&asset)
			
			if err == nil {
				excludeUserIDs = asset.AssignedUserIDs
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Build filter
	filter := bson.M{
		"organizationId": orgID,
		"deletedAt":      nil,
	}
	
	// Exclude already assigned users if asset ID provided
	if len(excludeUserIDs) > 0 {
		filter["_id"] = bson.M{"$nin": excludeUserIDs}
	}

	// Get available users
	cursor, err := userCollection.Find(ctx, filter, options.Find().SetSort(bson.D{{"lastName", 1}, {"firstName", 1}}))
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

	// Remove sensitive data
	for i := range users {
		users[i].PasswordHash = ""
	}

	if users == nil {
		users = []models.User{}
	}

	utils.RespondWithJSON(w, http.StatusOK, users)
}
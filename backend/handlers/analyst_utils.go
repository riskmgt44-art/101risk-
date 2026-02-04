package handlers

import (
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"riskmgt/models"
)

// Helper function to get analyst's assigned asset IDs
func getAnalystAssignedAssetIDs(ctx context.Context, userID, orgID primitive.ObjectID, role string) []primitive.ObjectID {
	var assetIDs []primitive.ObjectID
	
	// Only analysts have assigned assets
	if role != "analyst" {
		return []primitive.ObjectID{}
	}
	
	// Check if user has AssignedAssetIDs field populated
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err == nil {
		// If user has AssignedAssetIDs, use them
		if len(user.AssignedAssetIDs) > 0 {
			log.Printf("User %s has %d AssignedAssetIDs in user record", userID.Hex(), len(user.AssignedAssetIDs))
			assetIDs = append(assetIDs, user.AssignedAssetIDs...)
		}
	}
	
	// Check if user is owner of any assets
	cursor, err := assetCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"ownerUserId":    userID,
		"status":         bson.M{"$ne": "inactive"},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var asset struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			if err := cursor.Decode(&asset); err == nil {
				// Check if already in the list
				if !containsObjectID(assetIDs, asset.ID) {
					assetIDs = append(assetIDs, asset.ID)
					log.Printf("Added asset %s as owner asset", asset.ID.Hex())
				}
			}
		}
	}
	
	// Check if user is in assignedUserIds array
	cursor, err = assetCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"assignedUserIds": userID,
		"status":         bson.M{"$ne": "inactive"},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var asset struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			if err := cursor.Decode(&asset); err == nil {
				// Check if already in the list
				if !containsObjectID(assetIDs, asset.ID) {
					assetIDs = append(assetIDs, asset.ID)
					log.Printf("Added asset %s as assigned asset", asset.ID.Hex())
				}
			}
		}
	}
	
	log.Printf("Total assigned assets for user %s: %d", userID.Hex(), len(assetIDs))
	
	// Return empty slice instead of nil
	if len(assetIDs) == 0 {
		return []primitive.ObjectID{}
	}
	return assetIDs
}

// Helper function to get risk IDs for given assets
func getAnalystRiskIDsForAssets(ctx context.Context, orgID primitive.ObjectID, assetIDs []primitive.ObjectID) []primitive.ObjectID {
	var riskIDs []primitive.ObjectID
	
	if len(assetIDs) == 0 {
		return []primitive.ObjectID{} // Return empty slice instead of nil
	}
	
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"assetId": bson.M{"$in": assetIDs},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		log.Printf("Error getting risk IDs: %v", err)
		return []primitive.ObjectID{} // Return empty slice instead of nil
	}
	defer cursor.Close(ctx)
	
	for cursor.Next(ctx) {
		var risk struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&risk); err == nil {
			riskIDs = append(riskIDs, risk.ID)
		}
	}
	
	return riskIDs
}

// Helper function to get risk IDs created by specific user in assigned assets
func getAnalystRiskIDsForAssetsCreatedBy(ctx context.Context, orgID primitive.ObjectID, assetIDs []primitive.ObjectID, userID primitive.ObjectID) []primitive.ObjectID {
	var riskIDs []primitive.ObjectID
	
	if len(assetIDs) == 0 {
		return []primitive.ObjectID{} // Return empty slice instead of nil
	}
	
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"assetId": bson.M{"$in": assetIDs},
		"createdBy": userID,
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		return []primitive.ObjectID{} // Return empty slice instead of nil
	}
	defer cursor.Close(ctx)
	
	for cursor.Next(ctx) {
		var risk struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&risk); err == nil {
			riskIDs = append(riskIDs, risk.ID)
		}
	}
	
	return riskIDs
}

// Helper function to get action IDs for risks
func getAnalystActionIDsForRisks(ctx context.Context, orgID primitive.ObjectID, riskIDs []primitive.ObjectID) []primitive.ObjectID {
	var actionIDs []primitive.ObjectID
	
	if len(riskIDs) == 0 {
		return []primitive.ObjectID{} // Return empty slice instead of nil
	}
	
	cursor, err := actionCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"riskId": bson.M{"$in": riskIDs},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		log.Printf("Error getting action IDs: %v", err)
		return []primitive.ObjectID{} // Return empty slice instead of nil
	}
	defer cursor.Close(ctx)
	
	for cursor.Next(ctx) {
		var action struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&action); err == nil {
			actionIDs = append(actionIDs, action.ID)
		}
	}
	
	return actionIDs
}

// Helper function to check if slice contains ObjectID
func containsObjectID(slice []primitive.ObjectID, id primitive.ObjectID) bool {
	for _, existingID := range slice {
		if existingID == id {
			return true
		}
	}
	return false
}

// Add this function to analyst_utils.go for better asset handling
func getAnalystAssetDetails(ctx context.Context, orgID primitive.ObjectID, userID primitive.ObjectID, role string) ([]map[string]interface{}, error) {
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, role)
	
	if len(assignedAssetIDs) == 0 {
		return []map[string]interface{}{}, nil
	}
	
	cursor, err := assetCollection.Find(ctx, bson.M{
		"_id":            bson.M{"$in": assignedAssetIDs},
		"organizationId": orgID,
		"status":         bson.M{"$ne": "inactive"},
	}, options.Find().SetSort(bson.D{{"name", 1}}))
	
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	
	var assets []models.Asset
	if err = cursor.All(ctx, &assets); err != nil {
		return nil, err
	}
	
	// Convert to map with minimal fields for dropdown
	result := make([]map[string]interface{}, len(assets))
	for i, asset := range assets {
		result[i] = map[string]interface{}{
			"_id":  asset.ID.Hex(),
			"name": asset.Name,
		}
	}
	
	return result, nil
}
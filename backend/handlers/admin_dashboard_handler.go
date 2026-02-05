package handlers

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"riskmgt/models"
	"riskmgt/utils"
)

func GetAdminDashboard(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user to determine access level
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get user's assigned asset IDs
	assignedAssetIDs := getUserAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Initialize result with zeros
	result := map[string]interface{}{
		"totalRisks":        0,
		"highSeverityRisks": 0,
		"openActions":       0,
		"overdueActions":    0,
		"pendingApprovals":  0,
		"activeUsers":       0,
		"auditEntries24h":   0,
		"recentRoleChanges": 0,
		"policyUpdates30d":  0,
		"userRole":          user.Role,
		"assignedAssets":    len(assignedAssetIDs),
	}
	
	// For superadmin, return all data without filtering
	if user.Role == "superadmin" || user.Role == "super-admin" {
		// No filtering needed for superadmin
		assignedAssetIDs = []primitive.ObjectID{}
	}
	
	// If no assigned assets for non-superadmin, return empty data
	if (user.Role == "admin" || user.Role == "risk_manager" || user.Role == "user") && len(assignedAssetIDs) == 0 {
		// Return data with zeros
		utils.RespondWithJSON(w, http.StatusOK, result)
		return
	}
	
	// Fetch all data in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Helper function to update result
	updateResult := func(key string, value interface{}) {
		mu.Lock()
		result[key] = value
		mu.Unlock()
	}
	
	// Build filters based on user role and assigned assets
	var assetFilter bson.M
	var riskFilter bson.M
	var actionFilter bson.M
	
	// Common filters for all roles
	baseOrgFilter := bson.M{"organizationId": orgID}
	
	// Asset filter - for admin/risk_manager/user, filter by assigned assets
	assetFilter = baseOrgFilter
	if user.Role != "superadmin" && user.Role != "super-admin" && len(assignedAssetIDs) > 0 {
		assetFilter["_id"] = bson.M{"$in": assignedAssetIDs}
	}
	
	// Risk filter - for admin/risk_manager/user, filter by assigned assets
	riskFilter = bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	}
	if user.Role != "superadmin" && user.Role != "super-admin" && len(assignedAssetIDs) > 0 {
		riskFilter["assetId"] = bson.M{"$in": assignedAssetIDs}
	}
	
	// Get risk IDs for assigned assets (for action filtering)
	riskIDs := getRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	
	// Action filter - for admin/risk_manager/user, filter by assigned risk IDs
	actionFilter = baseOrgFilter
	if user.Role != "superadmin" && user.Role != "super-admin" && len(riskIDs) > 0 {
		actionFilter["riskId"] = bson.M{"$in": riskIDs}
	}
	
	// Get owned assets for admin (assets where user is owner)
	var ownedAssetIDs []primitive.ObjectID
	if user.Role == "admin" || user.Role == "risk_manager" {
		cursor, err := assetCollection.Find(ctx, bson.M{
			"organizationId": orgID,
			"ownerUserId":    userID,
			"status":         "active",
		}, options.Find().SetProjection(bson.M{"_id": 1}))
		
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var asset struct {
					ID primitive.ObjectID `bson:"_id"`
				}
				if err := cursor.Decode(&asset); err == nil {
					ownedAssetIDs = append(ownedAssetIDs, asset.ID)
				}
			}
		}
	}
	
	// Add owned assets to result
	result["ownedAssets"] = len(ownedAssetIDs)
	
	// 1. Total Risks
	wg.Add(1)
	go func() {
		defer wg.Done()
		count, _ := riskCollection.CountDocuments(ctx, riskFilter)
		updateResult("totalRisks", count)
	}()
	
	// 2. High Severity Risks
	wg.Add(1)
	go func() {
		defer wg.Done()
		highRiskFilter := bson.M{}
		for k, v := range riskFilter {
			highRiskFilter[k] = v
		}
		highRiskFilter["$or"] = []bson.M{
			{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
			{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
		}
		count, _ := riskCollection.CountDocuments(ctx, highRiskFilter)
		updateResult("highSeverityRisks", count)
	}()
	
	// 3. Open Actions
	wg.Add(1)
	go func() {
		defer wg.Done()
		openFilter := bson.M{}
		for k, v := range actionFilter {
			openFilter[k] = v
		}
		openFilter["status"] = bson.M{"$in": []string{"open", "in-progress", "on-hold"}}
		count, _ := actionCollection.CountDocuments(ctx, openFilter)
		updateResult("openActions", count)
	}()
	
	// 4. Overdue Actions
	wg.Add(1)
	go func() {
		defer wg.Done()
		overdueFilter := bson.M{}
		for k, v := range actionFilter {
			overdueFilter[k] = v
		}
		overdueFilter["status"] = bson.M{"$in": []string{"open", "in-progress"}}
		overdueFilter["dueDate"] = bson.M{"$lt": time.Now()}
		count, _ := actionCollection.CountDocuments(ctx, overdueFilter)
		updateResult("overdueActions", count)
	}()
	
	// 5. Pending Approvals - filter by risk IDs if admin has assigned assets
	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalFilter := bson.M{
			"organizationId": orgID,
			"status": "pending",
		}
		
		// If admin has assigned assets, filter approvals by risk IDs
		if user.Role != "superadmin" && user.Role != "super-admin" && len(riskIDs) > 0 {
			approvalFilter["riskId"] = bson.M{"$in": riskIDs}
		}
		count, _ := approvalCollection.CountDocuments(ctx, approvalFilter)
		updateResult("pendingApprovals", count)
	}()
	
	// 6. Active Users (logged in last 24 hours)
	wg.Add(1)
	go func() {
		defer wg.Done()
		twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
		count, _ := userCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"isActive": true,
			"$or": []bson.M{
				{"lastLogin": bson.M{"$gte": twentyFourHoursAgo}},
				{"activeSessions": bson.M{"$gt": 0}},
			},
		})
		updateResult("activeUsers", count)
	}()
	
	// 7. Audit entries in last 24 hours - filter by assigned assets/risks
	wg.Add(1)
	go func() {
		defer wg.Done()
		twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
		auditFilter := bson.M{
			"organizationId": orgID,
			"createdAt": bson.M{"$gte": twentyFourHoursAgo},
		}
		
		// Filter by entity IDs if admin has assigned assets
		if user.Role != "superadmin" && user.Role != "super-admin" {
			var orConditions []bson.M
			
			// Add asset-related audit logs
			if len(assignedAssetIDs) > 0 {
				orConditions = append(orConditions, bson.M{
					"$and": []bson.M{
						{"entityType": "asset"},
						{"entityID": bson.M{"$in": assignedAssetIDs}},
					},
				})
			}
			
			// Add risk-related audit logs
			if len(riskIDs) > 0 {
				orConditions = append(orConditions, bson.M{
					"$and": []bson.M{
						{"entityType": "risk"},
						{"entityID": bson.M{"$in": riskIDs}},
					},
				})
			}
			
			// Add action-related audit logs
			if len(riskIDs) > 0 {
				// Get action IDs for assigned risks
				var actionIDs []primitive.ObjectID
				cursor, err := actionCollection.Find(ctx, bson.M{
					"organizationId": orgID,
					"riskId": bson.M{"$in": riskIDs},
				}, options.Find().SetProjection(bson.M{"_id": 1}))
				
				if err == nil {
					defer cursor.Close(ctx)
					for cursor.Next(ctx) {
						var action struct {
							ID primitive.ObjectID `bson:"_id"`
						}
						if err := cursor.Decode(&action); err == nil {
							actionIDs = append(actionIDs, action.ID)
						}
					}
				}
				
				if len(actionIDs) > 0 {
					orConditions = append(orConditions, bson.M{
						"$and": []bson.M{
							{"entityType": "action"},
							{"entityID": bson.M{"$in": actionIDs}},
						},
					})
				}
			}
			
			if len(orConditions) > 0 {
				auditFilter["$or"] = orConditions
			} else {
				// If no assigned assets/risks, return 0 audit entries
				updateResult("auditEntries24h", 0)
				return
			}
		}
		
		count, _ := auditLogCollection.CountDocuments(ctx, auditFilter)
		updateResult("auditEntries24h", count)
	}()
	
	// 8. Recent role changes (last 30 days) - only show if superadmin
	wg.Add(1)
	go func() {
		defer wg.Done()
		thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)
		
		// Only superadmin can see role changes
		if user.Role == "superadmin" || user.Role == "super-admin" {
			// Count audit logs for role changes
			count, _ := auditLogCollection.CountDocuments(ctx, bson.M{
				"organizationId": orgID,
				"action": bson.M{"$regex": "role", "$options": "i"},
				"createdAt": bson.M{"$gte": thirtyDaysAgo},
			})
			updateResult("recentRoleChanges", count)
		} else {
			updateResult("recentRoleChanges", 0)
		}
	}()
	
	// 9. Policy updates (last 30 days) - only show if superadmin
	wg.Add(1)
	go func() {
		defer wg.Done()
		thirtyDaysAgo := time.Now().Add(-30 * 24 * time.Hour)
		
		// Only superadmin can see policy updates
		if user.Role == "superadmin" || user.Role == "super-admin" {
			// Count audit logs for policy-related actions
			count, _ := auditLogCollection.CountDocuments(ctx, bson.M{
				"organizationId": orgID,
				"entityType": "policy",
				"createdAt": bson.M{"$gte": thirtyDaysAgo},
			})
			updateResult("policyUpdates30d", count)
		} else {
			updateResult("policyUpdates30d", 0)
		}
	}()
	
	// 10. Get assigned asset names for the dashboard
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(assignedAssetIDs) > 0 {
			cursor, err := assetCollection.Find(ctx, bson.M{
				"_id":            bson.M{"$in": assignedAssetIDs},
				"organizationId": orgID,
				"status":         "active",
			}, options.Find().SetProjection(bson.M{"name": 1, "_id": 1}))
			
			if err == nil {
				defer cursor.Close(ctx)
				var assets []struct {
					ID   primitive.ObjectID `bson:"_id" json:"id"`
					Name string             `bson:"name" json:"name"`
				}
				if err = cursor.All(ctx, &assets); err == nil {
					updateResult("assignedAssetDetails", assets)
				}
			}
		}
	}()
	
	wg.Wait()
	
	// Return the data in the format frontend expects
	utils.RespondWithJSON(w, http.StatusOK, result)
}

// Helper function to get user's assigned asset IDs
func getUserAssignedAssetIDs(ctx context.Context, userID, orgID primitive.ObjectID, role string) []primitive.ObjectID {
	var assetIDs []primitive.ObjectID
	
	// Super admin can see all assets - return empty to indicate no filtering
	if role == "super-admin" || role == "superadmin" {
		return assetIDs
	}
	
	// Check if user has AssetIDs field populated
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&user)
	if err == nil && len(user.AssetIDs) > 0 {
		assetIDs = append(assetIDs, user.AssetIDs...)
	}
	
	// Also check if user is owner of any assets
	cursor, err := assetCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"ownerUserId":    userID,
		"status":         "active",
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var asset struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			if err := cursor.Decode(&asset); err == nil {
				// Check if already in the list
				found := false
				for _, existingID := range assetIDs {
					if existingID == asset.ID {
						found = true
						break
					}
				}
				if !found {
					assetIDs = append(assetIDs, asset.ID)
				}
			}
		}
	}
	
	// Check asset assignment collection (for assignedUserIds)
	cursor, err = assetCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"assignedUserIds": userID,
		"status":         "active",
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var asset struct {
				ID primitive.ObjectID `bson:"_id"`
			}
			if err := cursor.Decode(&asset); err == nil {
				// Check if already in the list
				found := false
				for _, existingID := range assetIDs {
					if existingID == asset.ID {
						found = true
						break
					}
				}
				if !found {
					assetIDs = append(assetIDs, asset.ID)
				}
			}
		}
	}
	
	// Remove duplicates (just in case)
	uniqueAssets := make(map[primitive.ObjectID]bool)
	var uniqueAssetIDs []primitive.ObjectID
	for _, id := range assetIDs {
		if !uniqueAssets[id] {
			uniqueAssets[id] = true
			uniqueAssetIDs = append(uniqueAssetIDs, id)
		}
	}
	
	return uniqueAssetIDs
}

// Helper function to get risk IDs for given assets
func getRiskIDsForAssets(ctx context.Context, orgID primitive.ObjectID, assetIDs []primitive.ObjectID) []primitive.ObjectID {
	var riskIDs []primitive.ObjectID
	
	if len(assetIDs) == 0 {
		return riskIDs
	}
	
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"assetId": bson.M{"$in": assetIDs},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		return riskIDs
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
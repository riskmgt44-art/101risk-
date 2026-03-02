package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"riskmgt/models"
	"riskmgt/utils"
)

// GetViewerDashboard - Main dashboard for Viewer role (asset-filtered, read-only)
func GetViewerDashboard(w http.ResponseWriter, r *http.Request) {
	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	// Verify viewer role
	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required. Current role: "+role)
		return
	}

	// Validate ObjectIDs
	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Get viewer's assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	if len(assignedAssetIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
			"totalRisks":        0,
			"highSeverityRisks": 0,
			"openActions":       0,
			"overdueActions":    0,
			"assignedAssets":    0,
			"userRole":         "viewer",
			"message":          "No assets assigned to viewer",
			"lastUpdated":      time.Now().Format(time.RFC3339),
			"assignedAssetDetails": []map[string]interface{}{},
			"recentActivity": []map[string]interface{}{},
		})
		return
	}

	// Initialize result
	result := map[string]interface{}{
		"totalRisks":        0,
		"highSeverityRisks": 0,
		"openActions":       0,
		"overdueActions":    0,
		"assignedAssets":    len(assignedAssetIDs),
		"userRole":         "viewer",
		"lastUpdated":      time.Now().Format(time.RFC3339),
		"assignedAssetDetails": []map[string]interface{}{},
		"recentActivity": []map[string]interface{}{},
	}

	// Build filters for viewer (only assigned assets)
	riskFilter := bson.M{
		"organizationId": orgID,
		"assetId":       bson.M{"$in": assignedAssetIDs},
		"status":        bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	}

	// Get risk IDs for assigned assets
	riskIDs := getViewerRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	
	// Action filter - only actions linked to risks in assigned assets
	actionFilter := bson.M{
		"organizationId": orgID,
	}
	if len(riskIDs) > 0 {
		actionFilter["riskId"] = bson.M{"$in": riskIDs}
	}

	// Fetch data in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	var fetchErr error

	// Helper function to update result
	updateResult := func(key string, value interface{}) {
		mu.Lock()
		result[key] = value
		mu.Unlock()
	}

	// 1. Total Risks in assigned assets
	wg.Add(1)
	go func() {
		defer wg.Done()
		count, err := riskCollection.CountDocuments(ctx, riskFilter)
		if err != nil {
			mu.Lock()
			fetchErr = err
			mu.Unlock()
			return
		}
		updateResult("totalRisks", count)
	}()

	// 2. High Severity Risks in assigned assets
	wg.Add(1)
	go func() {
		defer wg.Done()
		highRiskFilter := bson.M{}
		for k, v := range riskFilter {
			highRiskFilter[k] = v
		}
		highRiskFilter["$or"] = []bson.M{
			{"severity": bson.M{"$in": []string{"High", "Critical", "Extreme"}}},
			{"impactLevel": bson.M{"$in": []string{"High", "Critical", "Extreme"}}},
			{"likelihoodLevel": bson.M{"$in": []string{"High", "Critical", "Extreme"}}},
		}
		count, err := riskCollection.CountDocuments(ctx, highRiskFilter)
		if err != nil {
			mu.Lock()
			fetchErr = err
			mu.Unlock()
			return
		}
		updateResult("highSeverityRisks", count)
	}()

	// 3. Open Actions in assigned assets
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(riskIDs) == 0 {
			updateResult("openActions", 0)
			return
		}
		
		openFilter := bson.M{}
		for k, v := range actionFilter {
			openFilter[k] = v
		}
		openFilter["status"] = bson.M{"$in": []string{"open", "in-progress", "in_progress", "on-hold", "on_hold", "pending", "proposed"}}
		
		count, err := actionCollection.CountDocuments(ctx, openFilter)
		if err != nil {
			mu.Lock()
			fetchErr = err
			mu.Unlock()
			return
		}
		updateResult("openActions", count)
	}()

	// 4. Overdue Actions in assigned assets
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(riskIDs) == 0 {
			updateResult("overdueActions", 0)
			return
		}
		
		overdueFilter := bson.M{}
		for k, v := range actionFilter {
			overdueFilter[k] = v
		}
		overdueFilter["status"] = bson.M{"$nin": []string{"completed", "closed", "approved"}}
		overdueFilter["dueDate"] = bson.M{"$lt": time.Now()}
		
		count, err := actionCollection.CountDocuments(ctx, overdueFilter)
		if err != nil {
			mu.Lock()
			fetchErr = err
			mu.Unlock()
			return
		}
		updateResult("overdueActions", count)
	}()

	// 5. Get assigned asset details
	wg.Add(1)
	go func() {
		defer wg.Done()
		cursor, err := assetCollection.Find(ctx, bson.M{
			"_id":            bson.M{"$in": assignedAssetIDs},
			"organizationId": orgID,
			"status":         bson.M{"$nin": []string{"inactive", "deleted"}},
		}, options.Find().
			SetProjection(bson.M{
				"_id":        1,
				"name":       1,
				"type":       1,
				"subProject": 1,
				"status":     1,
			}).
			SetSort(bson.M{"name": 1}))
		
		if err != nil {
			mu.Lock()
			fetchErr = err
			mu.Unlock()
			return
		}
		defer cursor.Close(ctx)
		
		var assets []map[string]interface{}
		for cursor.Next(ctx) {
			var asset map[string]interface{}
			if err := cursor.Decode(&asset); err != nil {
				continue
			}
			
			assetID, _ := asset["_id"].(primitive.ObjectID)
			name, _ := asset["name"].(string)
			assetType, _ := asset["type"].(string)
			subProject, _ := asset["subProject"].(string)
			status, _ := asset["status"].(string)
			
			assets = append(assets, map[string]interface{}{
				"id":         assetID.Hex(),
				"name":       name,
				"type":       assetType,
				"subProject": subProject,
				"status":     status,
			})
		}
		
		updateResult("assignedAssetDetails", assets)
	}()

	// 6. Get recent activity (last 7 days)
	wg.Add(1)
	go func() {
		defer wg.Done()
		sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
		
		var recentActivity []map[string]interface{}
		
		// Build audit filter
		var orConditions []bson.M
		
		// Asset activities
		orConditions = append(orConditions, bson.M{
			"entityType": "asset",
			"entityID": bson.M{"$in": assignedAssetIDs},
		})
		
		// Risk activities
		if len(riskIDs) > 0 {
			orConditions = append(orConditions, bson.M{
				"entityType": "risk",
				"entityID": bson.M{"$in": riskIDs},
			})
		}
		
		// Get action IDs for these risks
		if len(riskIDs) > 0 {
			actionIDs := getViewerActionIDsForRisks(ctx, orgID, riskIDs)
			if len(actionIDs) > 0 {
				orConditions = append(orConditions, bson.M{
					"entityType": "action",
					"entityID": bson.M{"$in": actionIDs},
				})
			}
		}
		
		if len(orConditions) > 0 {
			auditFilter := bson.M{
				"organizationId": orgID,
				"createdAt":      bson.M{"$gte": sevenDaysAgo},
				"$or":           orConditions,
			}
			
			cursor, err := auditLogCollection.Find(ctx, auditFilter, 
				options.Find().
					SetSort(bson.M{"createdAt": -1}).
					SetLimit(10))
			
			if err == nil {
				defer cursor.Close(ctx)
				for cursor.Next(ctx) {
					var log map[string]interface{}
					if err := cursor.Decode(&log); err == nil {
						action, _ := log["action"].(string)
						description, _ := log["description"].(string)
						if description == "" {
							description = action
						}
						entityType, _ := log["entityType"].(string)
						userName, _ := log["userName"].(string)
						if userName == "" {
							userName = "System"
						}
						
						var createdAt time.Time
						if ca, ok := log["createdAt"].(primitive.DateTime); ok {
							createdAt = ca.Time()
						} else if ca, ok := log["createdAt"].(time.Time); ok {
							createdAt = ca
						} else {
							createdAt = time.Now()
						}
						
						entityName, _ := log["entityName"].(string)
						
						activity := map[string]interface{}{
							"id":          log["_id"],
							"title":       action,
							"description": description,
							"time":        formatTimeAgo(createdAt),
							"type":        entityType,
							"user":        userName,
							"entityName":  entityName,
						}
						recentActivity = append(recentActivity, activity)
					}
				}
			}
		}
		
		updateResult("recentActivity", recentActivity)
	}()

	wg.Wait()
	
	if fetchErr != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch dashboard data: "+fetchErr.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, result)
}

// GetViewerAssets - Get assigned assets for viewer (read-only)
func GetViewerAssets(w http.ResponseWriter, r *http.Request) {
	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	if len(assignedAssetIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
			"assets": []interface{}{},
			"count":  0,
			"message": "No assets assigned to viewer",
		})
		return
	}

	// Get asset details
	cursor, err := assetCollection.Find(ctx, bson.M{
		"_id":            bson.M{"$in": assignedAssetIDs},
		"organizationId": orgID,
		"status":         bson.M{"$nin": []string{"inactive", "deleted"}},
	}, options.Find().
		SetProjection(bson.M{
			"_id":        1,
			"name":       1,
			"type":       1,
			"subProject": 1,
			"status":     1,
			"createdAt":  1,
		}).
		SetSort(bson.M{"name": 1}))

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch assets: "+err.Error())
		return
	}
	defer cursor.Close(ctx)

	var assets []map[string]interface{}
	for cursor.Next(ctx) {
		var asset map[string]interface{}
		if err := cursor.Decode(&asset); err != nil {
			continue
		}
		
		assetID, _ := asset["_id"].(primitive.ObjectID)
		name, _ := asset["name"].(string)
		assetType, _ := asset["type"].(string)
		subProject, _ := asset["subProject"].(string)
		status, _ := asset["status"].(string)
		
		assets = append(assets, map[string]interface{}{
			"id":         assetID.Hex(),
			"name":       name,
			"type":       assetType,
			"subProject": subProject,
			"status":     status,
			"createdAt":  asset["createdAt"],
		})
	}

	if err := cursor.Err(); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Cursor error: "+err.Error())
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"assets": assets,
		"count":  len(assets),
	})
}

// GetViewerRisks - Get risks for assigned assets (read-only)
func GetViewerRisks(w http.ResponseWriter, r *http.Request) {
	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Get assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	if len(assignedAssetIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
			"risks": []interface{}{},
			"total": 0,
			"page":  1,
			"limit": 20,
			"totalPages": 0,
			"message": "No assets assigned to viewer",
		})
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	page, limit := getPaginationParams(query)
	skip := (page - 1) * limit

	// Build filter
	filter := bson.M{
		"organizationId": orgID,
		"assetId":       bson.M{"$in": assignedAssetIDs},
	}

	// Apply additional filters from query
	if status := query.Get("status"); status != "" {
		filter["status"] = status
	}
	if severity := query.Get("severity"); severity != "" {
		filter["$or"] = []bson.M{
			{"severity": severity},
			{"impactLevel": severity},
			{"likelihoodLevel": severity},
		}
	}
	if search := query.Get("search"); search != "" {
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": search, "$options": "i"}},
			{"description": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// Get total count
	total, err := riskCollection.CountDocuments(ctx, filter)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to count risks: "+err.Error())
		return
	}

	// Get risks - return full documents for viewer list
	cursor, err := riskCollection.Find(ctx, filter, 
		options.Find().
			SetSort(bson.M{"createdAt": -1}).
			SetSkip(int64(skip)).
			SetLimit(int64(limit)))

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch risks: "+err.Error())
		return
	}
	defer cursor.Close(ctx)

	var risks []bson.M
	if err = cursor.All(ctx, &risks); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode risks: "+err.Error())
		return
	}

	// Convert to response format with proper ID conversion
	riskResponses := make([]map[string]interface{}, len(risks))
	for i, risk := range risks {
		response := make(map[string]interface{})
		
		for k, v := range risk {
			switch k {
			case "_id":
				if oid, ok := v.(primitive.ObjectID); ok {
					response["id"] = oid.Hex()
					response["_id"] = oid.Hex()
					// Also set riskId if not present
					if risk["riskId"] == nil {
						response["riskId"] = oid.Hex()
					}
				}
			case "assetId":
				if oid, ok := v.(primitive.ObjectID); ok {
					response["assetId"] = oid.Hex()
				} else {
					response["assetId"] = v
				}
			case "organizationId":
				// Skip
			case "createdAt", "updatedAt", "nextReviewDate", "exposureStartDate", "exposureEndDate":
				if dt, ok := v.(primitive.DateTime); ok {
					response[k] = dt.Time()
				} else {
					response[k] = v
				}
			default:
				response[k] = v
			}
		}
		
		// Ensure all fields are present
		ensureRiskFields(response)
		
		// Add asset name
		if assetID, ok := response["assetId"].(string); ok && assetID != "" {
			assetObjID, _ := primitive.ObjectIDFromHex(assetID)
			var asset bson.M
			err = assetCollection.FindOne(ctx, bson.M{"_id": assetObjID}).Decode(&asset)
			if err == nil {
				if name, ok := asset["name"].(string); ok {
					response["assetName"] = name
				}
			}
		}
		
		riskResponses[i] = response
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"risks":      riskResponses,
		"total":      total,
		"page":       page,
		"limit":      limit,
		"totalPages": int((total + int64(limit) - 1) / int64(limit)),
	})
}

// Helper function to ensure all risk fields are present
func ensureRiskFields(response map[string]interface{}) {
	// Ensure critical fields are present
	if response["causes"] == nil {
		response["causes"] = []interface{}{}
	}
	if response["consequences"] == nil {
		response["consequences"] = []interface{}{}
	}
	if response["riskOwnerName"] == nil {
		response["riskOwnerName"] = ""
	}
	if response["subProject"] == nil {
		response["subProject"] = ""
	}
	if response["projectRamCurrent"] == nil {
		response["projectRamCurrent"] = ""
	}
	if response["projectRamTarget"] == nil {
		response["projectRamTarget"] = ""
	}
	if response["projectRAMCurrent"] == nil {
		response["projectRAMCurrent"] = response["projectRamCurrent"]
	}
	if response["projectRAMTarget"] == nil {
		response["projectRAMTarget"] = response["projectRamTarget"]
	}
	if response["riskVisualRamCurrent"] == nil {
		response["riskVisualRamCurrent"] = ""
	}
	if response["riskVisualRamTarget"] == nil {
		response["riskVisualRamTarget"] = ""
	}
	if response["riskVisualRAMCurrent"] == nil {
		response["riskVisualRAMCurrent"] = response["riskVisualRamCurrent"]
	}
	if response["riskVisualRAMTarget"] == nil {
		response["riskVisualRAMTarget"] = response["riskVisualRamTarget"]
	}
	if response["hsseRamCurrent"] == nil {
		response["hsseRamCurrent"] = ""
	}
	if response["hsseRamTarget"] == nil {
		response["hsseRamTarget"] = ""
	}
	if response["hsseRAMCurrent"] == nil {
		response["hsseRAMCurrent"] = response["hsseRamCurrent"]
	}
	if response["hsseRAMTarget"] == nil {
		response["hsseRAMTarget"] = response["hsseRamTarget"]
	}
	if response["manageability"] == nil {
		response["manageability"] = ""
	}
	if response["occurenceLevel"] == nil {
		if response["occurrenceLevel"] != nil {
			response["occurenceLevel"] = response["occurrenceLevel"]
		} else {
			response["occurenceLevel"] = "Medium"
		}
	}
	if response["occurrenceLevel"] == nil {
		response["occurrenceLevel"] = response["occurenceLevel"]
	}
	if response["type"] == nil {
		response["type"] = "Downside"
	}
	if response["Type"] == nil {
		response["Type"] = response["type"]
	}
	if response["status"] == nil {
		response["status"] = "open"
	}
	if response["Status"] == nil {
		response["Status"] = response["status"]
	}
	if response["thresholdChanging"] == nil {
		response["thresholdChanging"] = false
	}
	if response["functionalAreaTECOP"] == nil {
		response["functionalAreaTECOP"] = ""
	}
	if response["event"] == nil {
		response["event"] = ""
	}
	if response["Event"] == nil {
		response["Event"] = response["event"]
	}
	if response["description"] == nil {
		response["description"] = ""
	}
	if response["Description"] == nil {
		response["Description"] = response["description"]
	}
	if response["title"] == nil {
		response["title"] = ""
	}
	if response["Title"] == nil {
		response["Title"] = response["title"]
	}
}

// GetViewerRisk - Get single risk (read-only) with full details
func GetViewerRisk(w http.ResponseWriter, r *http.Request) {
	// Extract risk ID from URL path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	var riskID string
	for i, part := range parts {
		if part == "risks" && i+1 < len(parts) {
			riskID = parts[i+1]
			break
		}
	}

	if riskID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Risk ID is required")
		return
	}

	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get risk ID
	riskObjID, err := primitive.ObjectIDFromHex(riskID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid risk ID: "+err.Error())
		return
	}

	// Get assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	// Get the full risk document as bson.M
	var risk bson.M
	err = riskCollection.FindOne(ctx, bson.M{
		"_id":              riskObjID,
		"organizationId":   orgID,
		"assetId":          bson.M{"$in": assignedAssetIDs},
	}).Decode(&risk)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Risk not found or not accessible")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch risk: "+err.Error())
		}
		return
	}

	// Build response with all fields
	response := make(map[string]interface{})

	for k, v := range risk {
		switch k {
		case "_id":
			if oid, ok := v.(primitive.ObjectID); ok {
				response["id"] = oid.Hex()
				response["_id"] = oid.Hex() // Keep original field name too
				// Also set riskId if not present
				if risk["riskId"] == nil {
					response["riskId"] = oid.Hex()
				}
			}
		case "assetId":
			if oid, ok := v.(primitive.ObjectID); ok {
				response["assetId"] = oid.Hex()
			} else {
				response["assetId"] = v
			}
		case "organizationId":
			// Skip
		case "createdAt", "updatedAt", "nextReviewDate", "exposureStartDate", "exposureEndDate":
			if dt, ok := v.(primitive.DateTime); ok {
				response[k] = dt.Time()
			} else {
				response[k] = v
			}
		default:
			response[k] = v
		}
	}

	// Ensure all fields are present
	ensureRiskFields(response)

	// Add asset name lookup
	if assetID, ok := response["assetId"].(string); ok && assetID != "" {
		assetObjID, _ := primitive.ObjectIDFromHex(assetID)
		var asset bson.M
		err = assetCollection.FindOne(ctx, bson.M{"_id": assetObjID}).Decode(&asset)
		if err == nil {
			if name, ok := asset["name"].(string); ok {
				response["assetName"] = name
			}
		}
	}

	// Add created/updated by names if possible
	if createdBy, ok := risk["createdBy"]; ok {
		response["createdBy"] = createdBy
		// Try to get user name
		if createdByID, ok := createdBy.(primitive.ObjectID); ok {
			var user bson.M
			err = userCollection.FindOne(ctx, bson.M{"_id": createdByID}).Decode(&user)
			if err == nil {
				if name, ok := user["name"].(string); ok {
					response["createdByName"] = name
				}
			}
		}
	}
	if response["createdByName"] == nil {
		response["createdByName"] = ""
	}
	
	if updatedBy, ok := risk["updatedBy"]; ok {
		response["updatedBy"] = updatedBy
		// Try to get user name
		if updatedByID, ok := updatedBy.(primitive.ObjectID); ok {
			var user bson.M
			err = userCollection.FindOne(ctx, bson.M{"_id": updatedByID}).Decode(&user)
			if err == nil {
				if name, ok := user["name"].(string); ok {
					response["updatedByName"] = name
				}
			}
		}
	}
	if response["updatedByName"] == nil {
		response["updatedByName"] = ""
	}

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// GetViewerActions - Get actions for assigned assets (read-only) with full details
func GetViewerActions(w http.ResponseWriter, r *http.Request) {
	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Get assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	if len(assignedAssetIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
			"actions": []interface{}{},
			"total":   0,
			"message": "No assets assigned to viewer",
		})
		return
	}

	// Get risk IDs for assigned assets
	riskIDs := getViewerRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	
	// Parse query parameters
	query := r.URL.Query()
	page, limit := getPaginationParams(query)
	skip := (page - 1) * limit

	// Build filter for actions
	filter := bson.M{
		"organizationId": orgID,
	}

	// If there are risk IDs, filter by them, otherwise return empty (no risks = no actions)
	if len(riskIDs) > 0 {
		filter["riskId"] = bson.M{"$in": riskIDs}
	} else {
		// No risks assigned, return empty array
		utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
			"actions": []interface{}{},
			"total":   0,
			"message": "No risks found for assigned assets",
		})
		return
	}

	// Apply additional filters
	if status := query.Get("status"); status != "" && status != "all" {
		filter["status"] = status
	}
	if priority := query.Get("priority"); priority != "" && priority != "all" {
		filter["priority"] = priority
	}
	if search := query.Get("search"); search != "" {
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": search, "$options": "i"}},
			{"description": bson.M{"$regex": search, "$options": "i"}},
		}
	}

	// Get total count
	total, err := actionCollection.CountDocuments(ctx, filter)
	if err != nil {
		log.Printf("Error counting actions: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to count actions")
		return
	}

	// Get actions with full details
	opts := options.Find().
		SetSort(bson.M{"createdAt": -1}).
		SetSkip(int64(skip)).
		SetLimit(int64(limit))

	cursor, err := actionCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("Error finding actions: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch actions")
		return
	}
	defer cursor.Close(ctx)

	var actions []bson.M
	if err = cursor.All(ctx, &actions); err != nil {
		log.Printf("Error decoding actions: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode actions")
		return
	}

	// Convert to response format with proper ID conversion
	actionResponses := make([]map[string]interface{}, len(actions))
	for i, action := range actions {
		response := make(map[string]interface{})
		
		for k, v := range action {
			switch k {
			case "_id":
				if oid, ok := v.(primitive.ObjectID); ok {
					response["id"] = oid.Hex()
					response["_id"] = oid.Hex()
					// Generate action ID if not present
					if action["actionId"] == nil {
						response["actionId"] = fmt.Sprintf("ACT-%s", oid.Hex()[:8])
					}
				}
			case "riskId":
				if oid, ok := v.(primitive.ObjectID); ok {
					response["riskId"] = oid.Hex()
					// Try to get risk title
					var risk bson.M
					err = riskCollection.FindOne(ctx, bson.M{"_id": oid}).Decode(&risk)
					if err == nil {
						if title, ok := risk["title"].(string); ok {
							response["riskTitle"] = title
						}
					}
				} else {
					response["riskId"] = v
				}
			case "organizationId":
				// Skip
			case "createdAt", "updatedAt", "startDate", "endDate", "dueDate", "completedDate":
				if dt, ok := v.(primitive.DateTime); ok {
					response[k] = dt.Time()
				} else if str, ok := v.(string); ok {
					// Try to parse string date
					if t, err := time.Parse(time.RFC3339, str); err == nil {
						response[k] = t
					} else if t, err := time.Parse("2006-01-02", str); err == nil {
						response[k] = t
					} else {
						response[k] = v
					}
				} else {
					response[k] = v
				}
			default:
				response[k] = v
			}
		}
		
		// Ensure all fields are present
		ensureActionFields(response)
		
		// Add asset name if available through risk
		if riskID, ok := response["riskId"].(string); ok && riskID != "" && riskID != "000000000000000000000000" {
			riskObjID, _ := primitive.ObjectIDFromHex(riskID)
			var risk bson.M
			err = riskCollection.FindOne(ctx, bson.M{"_id": riskObjID}).Decode(&risk)
			if err == nil {
				if assetID, ok := risk["assetId"].(primitive.ObjectID); ok {
					var asset bson.M
					err = assetCollection.FindOne(ctx, bson.M{"_id": assetID}).Decode(&asset)
					if err == nil {
						if name, ok := asset["name"].(string); ok {
							response["assetName"] = name
						}
					}
				}
			}
		}
		
		actionResponses[i] = response
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"actions":    actionResponses,
		"total":      total,
		"page":       page,
		"limit":      limit,
		"totalPages": int((total + int64(limit) - 1) / int64(limit)),
	})
}

// GetViewerActionByID - Get single action by ID (read-only) with full details
func GetViewerActionByID(w http.ResponseWriter, r *http.Request) {
	// Extract action ID from URL path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	var actionID string
	for i, part := range parts {
		if part == "actions" && i+1 < len(parts) {
			actionID = parts[i+1]
			break
		}
	}

	if actionID == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Action ID is required")
		return
	}

	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get action ID
	actionObjID, err := primitive.ObjectIDFromHex(actionID)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid action ID: "+err.Error())
		return
	}

	// Get assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	// Get the action
	var action bson.M
	err = actionCollection.FindOne(ctx, bson.M{
		"_id":            actionObjID,
		"organizationId": orgID,
	}).Decode(&action)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Action not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch action: "+err.Error())
		}
		return
	}

	// Check if action belongs to an asset the viewer can access
	if riskID, ok := action["riskId"].(primitive.ObjectID); ok && riskID != primitive.NilObjectID {
		var risk bson.M
		err = riskCollection.FindOne(ctx, bson.M{
			"_id": riskID,
			"assetId": bson.M{"$in": assignedAssetIDs},
		}).Decode(&risk)
		
		if err != nil {
			// Risk not in viewer's assets
			utils.RespondWithError(w, http.StatusForbidden, "You don't have permission to view this action")
			return
		}
	}

	// Build response
	response := make(map[string]interface{})
	
	for k, v := range action {
		switch k {
		case "_id":
			if oid, ok := v.(primitive.ObjectID); ok {
				response["id"] = oid.Hex()
				response["_id"] = oid.Hex()
				if action["actionId"] == nil {
					response["actionId"] = fmt.Sprintf("ACT-%s", oid.Hex()[:8])
				}
			}
		case "riskId":
			if oid, ok := v.(primitive.ObjectID); ok {
				response["riskId"] = oid.Hex()
				// Get risk title
				var risk bson.M
				err = riskCollection.FindOne(ctx, bson.M{"_id": oid}).Decode(&risk)
				if err == nil {
					if title, ok := risk["title"].(string); ok {
						response["riskTitle"] = title
					}
					if assetID, ok := risk["assetId"].(primitive.ObjectID); ok {
						var asset bson.M
						err = assetCollection.FindOne(ctx, bson.M{"_id": assetID}).Decode(&asset)
						if err == nil {
							if name, ok := asset["name"].(string); ok {
								response["assetName"] = name
							}
						}
					}
				}
			} else {
				response["riskId"] = v
			}
		case "organizationId":
			// Skip
		case "createdAt", "updatedAt", "startDate", "endDate", "dueDate", "completedDate":
			if dt, ok := v.(primitive.DateTime); ok {
				response[k] = dt.Time()
			} else if str, ok := v.(string); ok {
				if t, err := time.Parse(time.RFC3339, str); err == nil {
					response[k] = t
				} else if t, err := time.Parse("2006-01-02", str); err == nil {
					response[k] = t
				} else {
					response[k] = v
				}
			} else {
				response[k] = v
			}
		default:
			response[k] = v
		}
	}
	
	// Ensure all fields are present
	ensureActionFields(response)

	utils.RespondWithJSON(w, http.StatusOK, response)
}

// Helper function to ensure all action fields are present
func ensureActionFields(response map[string]interface{}) {
	if response["title"] == nil {
		response["title"] = ""
	}
	if response["description"] == nil {
		response["description"] = ""
	}
	if response["status"] == nil {
		response["status"] = "pending"
	}
	if response["priority"] == nil {
		response["priority"] = "medium"
	}
	if response["owner"] == nil {
		response["owner"] = ""
	}
	if response["cost"] == nil {
		response["cost"] = 0.0
	}
	if response["progress"] == nil {
		response["progress"] = 0
	}
	if response["notes"] == nil {
		response["notes"] = ""
	}
	if response["subProject"] == nil {
		response["subProject"] = ""
	}
	if response["type"] == nil {
		response["type"] = "preventive"
	}
	if response["auditTrailCount"] == nil {
		response["auditTrailCount"] = 0
	}
}

// GetViewerAuditLogs - Get audit logs for assigned assets (read-only)
func GetViewerAuditLogs(w http.ResponseWriter, r *http.Request) {
	userIDHex, orgIDHex, role, err := getAuthContext(r)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "Authentication required: "+err.Error())
		return
	}

	if role != "viewer" {
		utils.RespondWithError(w, http.StatusForbidden, "Viewer role required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID: "+err.Error())
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// Get assigned assets
	assignedAssetIDs, err := getViewerAssignedAssetIDs(ctx, userID, orgID)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to get assigned assets: "+err.Error())
		return
	}
	
	if len(assignedAssetIDs) == 0 {
		utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
			"auditLogs":  []interface{}{},
			"total":      0,
			"page":       1,
			"limit":      20,
			"totalPages": 0,
			"message":    "No assets assigned to viewer",
		})
		return
	}

	// Get risk IDs for assigned assets
	riskIDs := getViewerRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	
	// Build audit filter for assigned assets/risks
	var orConditions []bson.M
	
	// Asset activities
	orConditions = append(orConditions, bson.M{
		"entityType": "asset",
		"entityID": bson.M{"$in": assignedAssetIDs},
	})
	
	// Risk activities
	if len(riskIDs) > 0 {
		orConditions = append(orConditions, bson.M{
			"entityType": "risk",
			"entityID": bson.M{"$in": riskIDs},
		})
		
		// Get action IDs for these risks
		actionIDs := getViewerActionIDsForRisks(ctx, orgID, riskIDs)
		if len(actionIDs) > 0 {
			orConditions = append(orConditions, bson.M{
				"entityType": "action",
				"entityID": bson.M{"$in": actionIDs},
			})
		}
	}

	// Parse query parameters
	query := r.URL.Query()
	page, limit := getPaginationParams(query)
	skip := (page - 1) * limit

	// Build filter
	filter := bson.M{
		"organizationId": orgID,
		"$or":           orConditions,
	}

	// Apply time filter
	if startDate := query.Get("startDate"); startDate != "" {
		if startTime, err := time.Parse(time.RFC3339, startDate); err == nil {
			if filter["createdAt"] == nil {
				filter["createdAt"] = bson.M{"$gte": startTime}
			} else {
				filter["createdAt"].(bson.M)["$gte"] = startTime
			}
		}
	}
	if endDate := query.Get("endDate"); endDate != "" {
		if endTime, err := time.Parse(time.RFC3339, endDate); err == nil {
			if filter["createdAt"] == nil {
				filter["createdAt"] = bson.M{"$lte": endTime}
			} else {
				filter["createdAt"].(bson.M)["$lte"] = endTime
			}
		}
	}
	
	// Apply entity type filter
	if entityType := query.Get("entityType"); entityType != "" {
		filter["entityType"] = entityType
	}

	// Get total count
	total, err := auditLogCollection.CountDocuments(ctx, filter)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to count audit logs: "+err.Error())
		return
	}

	// Get audit logs
	cursor, err := auditLogCollection.Find(ctx, filter, 
		options.Find().
			SetSort(bson.M{"createdAt": -1}).
			SetSkip(int64(skip)).
			SetLimit(int64(limit)).
			SetProjection(bson.M{
				"_id":         1,
				"action":      1,
				"description": 1,
				"entityType":  1,
				"entityID":    1,
				"entityName":  1,
				"userName":    1,
				"ipAddress":   1,
				"createdAt":   1,
				"userAgent":   1,
			}))

	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch audit logs: "+err.Error())
		return
	}
	defer cursor.Close(ctx)

	var auditLogs []map[string]interface{}
	if err = cursor.All(ctx, &auditLogs); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode audit logs: "+err.Error())
		return
	}

	// Convert to response format
	logResponses := make([]map[string]interface{}, len(auditLogs))
	for i, log := range auditLogs {
		logID, _ := log["_id"].(primitive.ObjectID)
		action, _ := log["action"].(string)
		description, _ := log["description"].(string)
		entityType, _ := log["entityType"].(string)
		entityID, _ := log["entityID"].(primitive.ObjectID)
		entityName, _ := log["entityName"].(string)
		userName, _ := log["userName"].(string)
		ipAddress, _ := log["ipAddress"].(string)
		
		var createdAt time.Time
		if ca, ok := log["createdAt"].(primitive.DateTime); ok {
			createdAt = ca.Time()
		} else if ca, ok := log["createdAt"].(time.Time); ok {
			createdAt = ca
		}
		
		logResponses[i] = map[string]interface{}{
			"id":          logID.Hex(),
			"action":      action,
			"description": description,
			"entityType":  entityType,
			"entityID":    entityID.Hex(),
			"entityName":  entityName,
			"userName":    userName,
			"ipAddress":   ipAddress,
			"createdAt":   createdAt,
			"userAgent":   log["userAgent"],
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"auditLogs":  logResponses,
		"total":      total,
		"page":       page,
		"limit":      limit,
		"totalPages": int((total + int64(limit) - 1) / int64(limit)),
	})
}

// Helper function to get viewer's assigned asset IDs
func getViewerAssignedAssetIDs(ctx context.Context, userID, orgID primitive.ObjectID) ([]primitive.ObjectID, error) {
	var assetIDs []primitive.ObjectID
	
	// Check if user has AssignedAssetIDs field populated
	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err == nil && len(user.AssignedAssetIDs) > 0 {
		assetIDs = append(assetIDs, user.AssignedAssetIDs...)
	}
	
	// Check if user is in assignedUserIds array
	cursor, err := assetCollection.Find(ctx, bson.M{
		"organizationId":  orgID,
		"assignedUserIds": userID,
		"status":          bson.M{"$nin": []string{"inactive", "deleted"}},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		return assetIDs, err
	}
	defer cursor.Close(ctx)
	
	for cursor.Next(ctx) {
		var asset struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&asset); err == nil {
			// Check if already in the list
			if !containsObjectIDViewer(assetIDs, asset.ID) {
				assetIDs = append(assetIDs, asset.ID)
			}
		}
	}
	
	// Return empty slice instead of nil
	if len(assetIDs) == 0 {
		return []primitive.ObjectID{}, nil
	}
	return assetIDs, nil
}

// Helper function to get risk IDs for assets (viewer-specific version)
func getViewerRiskIDsForAssets(ctx context.Context, orgID primitive.ObjectID, assetIDs []primitive.ObjectID) []primitive.ObjectID {
	if len(assetIDs) == 0 {
		return []primitive.ObjectID{}
	}
	
	var riskIDs []primitive.ObjectID
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"assetId":        bson.M{"$in": assetIDs},
		"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived", "deleted"}},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		return []primitive.ObjectID{}
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

// Helper function to get action IDs for risks (viewer-specific version)
func getViewerActionIDsForRisks(ctx context.Context, orgID primitive.ObjectID, riskIDs []primitive.ObjectID) []primitive.ObjectID {
	if len(riskIDs) == 0 {
		return []primitive.ObjectID{}
	}
	
	var actionIDs []primitive.ObjectID
	cursor, err := actionCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"riskId":         bson.M{"$in": riskIDs},
	}, options.Find().SetProjection(bson.M{"_id": 1}))
	
	if err != nil {
		return []primitive.ObjectID{}
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

// Helper function to extract auth context
func getAuthContext(r *http.Request) (userID, orgID, role string, err error) {
	// Try to get from context first (JWT middleware)
	userIDVal := r.Context().Value("userID")
	orgIDVal := r.Context().Value("orgID")
	roleVal := r.Context().Value("role")
	
	if userIDVal != nil {
		userID = userIDVal.(string)
	}
	if orgIDVal != nil {
		orgID = orgIDVal.(string)
	}
	if roleVal != nil {
		role = roleVal.(string)
	}
	
	// If context values are empty, try to extract from JWT token in Authorization header
	if userID == "" || orgID == "" || role == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			
			// Parse JWT token
			tokenParts := strings.Split(tokenStr, ".")
			if len(tokenParts) == 3 {
				payload := tokenParts[1]
				// Decode base64 payload
				decoded, decodeErr := base64.RawURLEncoding.DecodeString(payload)
				if decodeErr == nil {
					var claims map[string]interface{}
					if json.Unmarshal(decoded, &claims) == nil {
						if userID == "" {
							if uid, ok := claims["userID"].(string); ok {
								userID = uid
							} else if uid, ok := claims["userId"].(string); ok {
								userID = uid
							} else if uid, ok := claims["sub"].(string); ok {
								userID = uid
							}
						}
						
						if orgID == "" {
							if oid, ok := claims["organizationId"].(string); ok {
								orgID = oid
							} else if oid, ok := claims["orgID"].(string); ok {
								orgID = oid
							} else if oid, ok := claims["orgId"].(string); ok {
								orgID = oid
							}
						}
						
						if role == "" {
							if r, ok := claims["role"].(string); ok {
								role = r
							}
						}
					}
				}
			}
		}
	}
	
	// Validate required fields
	if userID == "" {
		err = fmt.Errorf("userID not found in request")
		return
	}
	if orgID == "" {
		err = fmt.Errorf("organizationId not found in request")
		return
	}
	if role == "" {
		err = fmt.Errorf("role not found in request")
		return
	}
	
	return
}

// Helper function for time formatting
func formatTimeAgo(t time.Time) string {
	duration := time.Since(t)
	
	switch {
	case duration < time.Minute:
		return "just now"
	case duration < time.Hour:
		minutes := int(duration.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	case duration < 24*time.Hour:
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case duration < 7*24*time.Hour:
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	case duration < 30*24*time.Hour:
		weeks := int(duration.Hours() / (24 * 7))
		if weeks == 1 {
			return "1 week ago"
		}
		return fmt.Sprintf("%d weeks ago", weeks)
	case duration < 365*24*time.Hour:
		months := int(duration.Hours() / (24 * 30))
		if months == 1 {
			return "1 month ago"
		}
		return fmt.Sprintf("%d months ago", months)
	default:
		return t.Format("Jan 02, 2006")
	}
}

// Helper function to get pagination parameters
func getPaginationParams(query map[string][]string) (page, limit int) {
	page = 1
	limit = 20
	
	// Direct map access
	if pValues, ok := query["page"]; ok && len(pValues) > 0 {
		p := pValues[0]
		if pInt := parseInt(p); pInt > 0 {
			page = pInt
		}
	}
	
	if lValues, ok := query["limit"]; ok && len(lValues) > 0 {
		l := lValues[0]
		if lInt := parseInt(l); lInt > 0 && lInt <= 100 {
			limit = lInt
		}
	}
	
	return page, limit
}

// Helper function to parse int from string
func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

// Helper function to check if object ID is in slice
func containsObjectIDViewer(slice []primitive.ObjectID, item primitive.ObjectID) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
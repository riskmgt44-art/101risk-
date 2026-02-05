package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"riskmgt/models"
	"riskmgt/utils"
)

// GetAnalystRisks - FIXED VERSION that matches frontend expectations
func GetAnalystRisks(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get analyst's assigned asset IDs
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Build filter
	filter := bson.M{
		"organizationId": orgID,
	}
	
	// If analyst has assigned assets, filter by them
	if len(assignedAssetIDs) > 0 {
		filter["$or"] = []bson.M{
			{"assetId": bson.M{"$in": assignedAssetIDs}},
			{"createdBy": userID}, // Also include risks created by the analyst
		}
	} else {
		// If no assigned assets, show only risks created by the analyst
		filter["createdBy"] = userID
	}
	
	// Apply query filters
	query := r.URL.Query()
	
	// Status filter
	if status := query.Get("status"); status != "" && status != "all" {
		if status == "active" {
			filter["status"] = bson.M{"$nin": []string{"closed", "mitigated", "archived"}}
		} else {
			filter["status"] = status
		}
	}
	
	// Type filter
	if riskType := query.Get("type"); riskType != "" && riskType != "all" {
		filter["type"] = riskType
	}
	
	// Search filter
	if search := query.Get("search"); search != "" {
		filter["$or"] = []bson.M{
			{"title": bson.M{"$regex": search, "$options": "i"}},
			{"description": bson.M{"$regex": search, "$options": "i"}},
			{"riskId": bson.M{"$regex": search, "$options": "i"}},
		}
	}
	
	// Execute query
	cursor, err := riskCollection.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
				"risks": []map[string]interface{}{},
			})
			return
		}
		log.Printf("Error fetching analyst risks: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch risks")
		return
	}
	defer cursor.Close(ctx)
	
	var risks []models.Risk
	if err = cursor.All(ctx, &risks); err != nil {
		log.Printf("Error decoding analyst risks: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to decode risks")
		return
	}
	
	if risks == nil {
		risks = []models.Risk{}
	}
	
	// Get asset details for each risk and create response
	riskResponse := make([]map[string]interface{}, len(risks))
	for i, risk := range risks {
		riskMap := make(map[string]interface{})
		
		// Convert risk to map
		data, _ := bson.Marshal(risk)
		bson.Unmarshal(data, &riskMap)
		
		// Get asset name if asset exists
		assetName := ""
		if !risk.AssetID.IsZero() {
			var asset models.Asset
			err := assetCollection.FindOne(ctx, bson.M{
				"_id":            risk.AssetID,
				"organizationId": orgID,
			}).Decode(&asset)
			if err == nil {
				assetName = asset.Name
			}
		}
		
		// Set fields with correct names for frontend
		riskMap["assetName"] = assetName
		
		// Ensure all expected fields exist (set defaults if missing)
		if riskMap["riskId"] == nil {
			riskMap["riskId"] = fmt.Sprintf("R%04d", i+1)
		}
		
		// Convert causes and consequences to arrays
		if risk.Causes != nil {
			riskMap["causes"] = risk.Causes
		} else {
			riskMap["causes"] = []string{}
		}
		
		if risk.Consequences != nil {
			riskMap["consequences"] = risk.Consequences
		} else {
			riskMap["consequences"] = []string{}
		}
		
		// Handle risk owner name - combine first and last name
		if risk.RiskOwnerName != "" {
			riskMap["riskOwnerName"] = risk.RiskOwnerName
		} else {
			// Fallback to user's name
			userName := fmt.Sprintf("%s %s", user.FirstName, user.LastName)
			if userName == " " {
				userName = user.Email
			}
			riskMap["riskOwnerName"] = userName
		}
		
		// Handle RAM fields
		if risk.ProjectRAMCurrent != "" {
			riskMap["projectRamCurrent"] = risk.ProjectRAMCurrent
		}
		
		if risk.ProjectRAMTarget != "" {
			riskMap["projectRamTarget"] = risk.ProjectRAMTarget
		}
		
		if risk.RiskVisualRAMCurrent != "" {
			riskMap["riskVisualRamCurrent"] = risk.RiskVisualRAMCurrent
		}
		
		if risk.RiskVisualRAMTarget != "" {
			riskMap["riskVisualRamTarget"] = risk.RiskVisualRAMTarget
		}
		
		if risk.HSSE_RAMCurrent != "" {
			riskMap["hsseRamCurrent"] = risk.HSSE_RAMCurrent
		}
		
		if risk.HSSE_RAMTarget != "" {
			riskMap["hsseRamTarget"] = risk.HSSE_RAMTarget
		}
		
		riskResponse[i] = riskMap
	}
	
	// Return in format expected by frontend
	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"risks": riskResponse,
	})
}

// CreateAnalystRisk - FIXED VERSION that matches frontend format
func CreateAnalystRisk(w http.ResponseWriter, r *http.Request) {
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
	
	userID, err := primitive.ObjectIDFromHex(userIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	
	// Get user to verify role
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Only analysts can use this endpoint
	if user.Role != "analyst" {
		utils.RespondWithError(w, http.StatusForbidden, "Only analysts can use this endpoint")
		return
	}
	
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}
	
	// Validate required fields
	title, ok := req["title"].(string)
	if !ok || title == "" || len(title) > 200 {
		utils.RespondWithError(w, http.StatusBadRequest, "Title is required and must be less than 200 characters")
		return
	}
	
	description, ok := req["description"].(string)
	if !ok || description == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Description is required")
		return
	}
	
	riskType, ok := req["type"].(string)
	if !ok || riskType == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Type is required")
		return
	}
	
	occurenceLevel, ok := req["occurenceLevel"].(string)
	if !ok || occurenceLevel == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Occurrence level is required")
		return
	}
	
	// Validate asset ID if provided
	var assetID primitive.ObjectID
	if assetIDStr, ok := req["assetId"].(string); ok && assetIDStr != "" {
		assetID, err = primitive.ObjectIDFromHex(assetIDStr)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "Invalid asset ID")
			return
		}
		
		// Verify asset exists and is assigned to analyst
		assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
		
		assetAssigned := false
		for _, assignedID := range assignedAssetIDs {
			if assignedID == assetID {
				assetAssigned = true
				break
			}
		}
		
		if !assetAssigned {
			utils.RespondWithError(w, http.StatusForbidden, "You can only create risks for your assigned assets")
			return
		}
		
		// Verify asset exists in organization
		assetCount, err := assetCollection.CountDocuments(ctx, bson.M{
			"_id":            assetID,
			"organizationId": orgID,
		})
		if err != nil || assetCount == 0 {
			utils.RespondWithError(w, http.StatusBadRequest, "Asset not found")
			return
		}
	}
	
	// Parse dates
	parseDateFromMap := func(field string) *time.Time {
		if dateStr, ok := req[field].(string); ok && dateStr != "" {
			if parsed, err := time.Parse("2006-01-02", dateStr); err == nil {
				return &parsed
			}
		}
		return nil
	}
	
	nextReviewDate := parseDateFromMap("nextReviewDate")
	exposureStartDate := parseDateFromMap("exposureStartDate")
	exposureEndDate := parseDateFromMap("exposureEndDate")
	
	// Validate exposure dates
	if exposureStartDate != nil && exposureEndDate != nil {
		if exposureEndDate.Before(*exposureStartDate) {
			utils.RespondWithError(w, http.StatusBadRequest, "exposureEndDate must be after exposureStartDate")
			return
		}
	}
	
	// Parse bowtie causes and consequences from frontend data
	var bowtieCauses []models.Cause
	var bowtieConsequences []models.Consequence
	
	// Parse causes if provided in bowtie structure
	if causesData, ok := req["causes"]; ok {
		// Check if it's an array of maps (bowtie structure)
		if causeMaps, ok := causesData.([]interface{}); ok {
			for i, causeData := range causeMaps {
				if causeMap, ok := causeData.(map[string]interface{}); ok {
					// Extract cause description
					causeDesc, _ := causeMap["description"].(string)
					
					cause := models.Cause{
						ID:          primitive.NewObjectID(),
						Title:       fmt.Sprintf("Cause %d", i+1),
						Description: causeDesc,
						CreatedAt:   time.Now().UTC(),
						UpdatedAt:   time.Now().UTC(),
					}
					
					// Parse actions for this cause
					if actionsData, ok := causeMap["actions"].([]interface{}); ok {
						for _, actionData := range actionsData {  // FIXED: Changed j to _
							if actionMap, ok := actionData.(map[string]interface{}); ok {
								actionTitle, _ := actionMap["title"].(string)
								actionOwner, _ := actionMap["owner"].(string)
								
								var dueDate *time.Time
								if dueDateStr, ok := actionMap["dueDate"].(string); ok && dueDateStr != "" {
									if parsed, err := time.Parse("2006-01-02", dueDateStr); err == nil {
										dueDate = &parsed
									}
								}
								
								actionStatus := "not_started"
								if status, ok := actionMap["status"].(string); ok {
									actionStatus = status
								}
								
								action := models.RiskAction{
									ID:          primitive.NewObjectID(),
									Title:       actionTitle,
									Description: actionTitle,
									Type:        "preventive",
									Owner:       actionOwner,
									DueDate:     dueDate,
									Status:      actionStatus,
									CreatedAt:   time.Now().UTC(),
									UpdatedAt:   time.Now().UTC(),
								}
								
								cause.Actions = append(cause.Actions, action)
							}
						}
					}
					
					bowtieCauses = append(bowtieCauses, cause)
				}
			}
		}
	}
	
	// Parse consequences if provided in bowtie structure
	if consequencesData, ok := req["consequences"]; ok {
		// Check if it's an array of maps (bowtie structure)
		if consequenceMaps, ok := consequencesData.([]interface{}); ok {
			for i, consequenceData := range consequenceMaps {
				if consequenceMap, ok := consequenceData.(map[string]interface{}); ok {
					// Extract consequence description
					consequenceDesc, _ := consequenceMap["description"].(string)
					
					consequence := models.Consequence{
						ID:          primitive.NewObjectID(),
						Title:       fmt.Sprintf("Consequence %d", i+1),
						Description: consequenceDesc,
						CreatedAt:   time.Now().UTC(),
						UpdatedAt:   time.Now().UTC(),
					}
					
					// Parse controls for this consequence
					if controlsData, ok := consequenceMap["controls"].([]interface{}); ok {
						for _, controlData := range controlsData {  // FIXED: Changed j to _
							if controlMap, ok := controlData.(map[string]interface{}); ok {
								controlTitle, _ := controlMap["title"].(string)
								controlOwner, _ := controlMap["owner"].(string)
								
								var dueDate *time.Time
								if dueDateStr, ok := controlMap["dueDate"].(string); ok && dueDateStr != "" {
									if parsed, err := time.Parse("2006-01-02", dueDateStr); err == nil {
										dueDate = &parsed
									}
								}
								
								controlStatus := "not_started"
								if status, ok := controlMap["status"].(string); ok {
									controlStatus = status
								}
								
								action := models.RiskAction{
									ID:          primitive.NewObjectID(),
									Title:       controlTitle,
									Description: controlTitle,
									Type:        "recovery",
									Owner:       controlOwner,
									DueDate:     dueDate,
									Status:      controlStatus,
									CreatedAt:   time.Now().UTC(),
									UpdatedAt:   time.Now().UTC(),
								}
								
								consequence.Actions = append(consequence.Actions, action)
							}
						}
					}
					
					bowtieConsequences = append(bowtieConsequences, consequence)
				}
			}
		}
	}
	
	// Generate risk ID
	riskID := generateRiskID()
	
	// Create risk with "pending" status (requires approval)
	risk := models.Risk{
		ID:                    primitive.NewObjectID(),
		OrganizationID:        orgID,
		RiskID:                riskID,
		Title:                 title,
		Description:           description,
		Type:                  riskType,
		Status:                "pending",
		RiskOwnerName:         getStringFromMap(req, "riskOwnerName"),
		SubProject:            getStringFromMap(req, "subProject"),
		NextReviewDate:        nextReviewDate,
		ExposureStartDate:     exposureStartDate,
		ExposureEndDate:       exposureEndDate,
		OccurenceLevel:        occurenceLevel,
		AssetID:               assetID,
		LinkedAssets:          []string{},
		AuditTrailCount:       1,
		LinkedActions:         []string{},
		ProjectRAMCurrent:     getStringFromMap(req, "projectRamCurrent"),
		ProjectRAMTarget:      getStringFromMap(req, "projectRamTarget"),
		RiskVisualRAMCurrent:  getStringFromMap(req, "riskVisualRamCurrent"),
		RiskVisualRAMTarget:   getStringFromMap(req, "riskVisualRamTarget"),
		HSSE_RAMCurrent:       getStringFromMap(req, "hsseRamCurrent"),
		HSSE_RAMTarget:        getStringFromMap(req, "hsseRamTarget"),
		Manageability:         getStringFromMap(req, "manageability"),
		FunctionalAreaTECOP:   getStringFromMap(req, "functionalAreaTECOP"),
		ThresholdChanging:     getBoolFromMap(req, "thresholdChanging"),
		BowtieCauses:          bowtieCauses,
		BowtieConsequences:    bowtieConsequences,
		CreatedBy:             userID,
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}
	
	// For backward compatibility - also store causes/consequences as string arrays
	var causeStrings []string
	var consequenceStrings []string
	
	for _, cause := range bowtieCauses {
		if cause.Description != "" {
			causeStrings = append(causeStrings, cause.Description)
		}
	}
	
	for _, consequence := range bowtieConsequences {
		if consequence.Description != "" {
			consequenceStrings = append(consequenceStrings, consequence.Description)
		}
	}
	
	risk.Causes = causeStrings
	risk.Consequences = consequenceStrings
	
	// Insert risk
	_, err = riskCollection.InsertOne(ctx, risk)
	if err != nil {
		log.Printf("Error creating analyst risk: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create risk")
		return
	}
	
	// Get asset name for response
	assetName := ""
	if !assetID.IsZero() {
		var asset models.Asset
		err := assetCollection.FindOne(ctx, bson.M{
			"_id":            assetID,
			"organizationId": orgID,
		}).Decode(&asset)
		if err == nil {
			assetName = asset.Name
		}
	}
	
	// Convert risk to response format
	riskResponse := make(map[string]interface{})
	data, _ := bson.Marshal(risk)
	bson.Unmarshal(data, &riskResponse)
	
	riskResponse["assetName"] = assetName
	riskResponse["riskOwnerName"] = risk.RiskOwnerName
	
	// Create audit log
	userName, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)
	
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		UserEmail:      userName,
		UserRole:       userRole,
		Action:         "analyst_risk_create",
		EntityType:     "risk",
		EntityID:       risk.ID,
		Details:        bson.M{"title": title, "type": riskType, "riskId": riskID, "status": "pending", "bowtie": len(bowtieCauses) > 0},
		CreatedAt:      time.Now().UTC(),
		IPAddress:      r.RemoteAddr,
		UserAgent:      r.UserAgent(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)
	
	utils.RespondWithJSON(w, http.StatusCreated, map[string]interface{}{
		"message":  "Risk created successfully and submitted for approval",
		"risk":     riskResponse,
	})
}

// GetAnalystRisk - FIXED VERSION for single risk
func GetAnalystRisk(w http.ResponseWriter, r *http.Request) {
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
	
	// Get risk ID from path parameter
	vars := mux.Vars(r)
	riskIDStr := vars["id"]
	if riskIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Risk ID required")
		return
	}
	
	riskID, err := primitive.ObjectIDFromHex(riskIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid risk ID format")
		return
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get the risk
	var risk models.Risk
	err = riskCollection.FindOne(ctx, bson.M{"_id": riskID, "organizationId": orgID}).Decode(&risk)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "Risk not found")
			return
		}
		log.Printf("Error fetching risk: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch risk")
		return
	}
	
	// Check if analyst has access to this risk
	hasAccess := false
	
	// Analysts can always see risks they created
	if risk.CreatedBy == userID {
		hasAccess = true
	} else {
		// Check if risk is in their assigned assets
		assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
		for _, assetID := range assignedAssetIDs {
			if assetID == risk.AssetID {
				hasAccess = true
				break
			}
		}
	}
	
	if !hasAccess {
		utils.RespondWithError(w, http.StatusForbidden, "You do not have access to this risk")
		return
	}
	
	// Get asset details if available
	riskResponse := make(map[string]interface{})
	data, _ := bson.Marshal(risk)
	bson.Unmarshal(data, &riskResponse)
	
	assetName := ""
	if !risk.AssetID.IsZero() {
		var asset models.Asset
		err := assetCollection.FindOne(ctx, bson.M{
			"_id":            risk.AssetID,
			"organizationId": orgID,
		}).Decode(&asset)
		if err == nil {
			assetName = asset.Name
			riskResponse["assetName"] = asset.Name
			riskResponse["assetCategory"] = asset.Category
			riskResponse["assetLocation"] = asset.Location
		}
	}
	
	// Add missing fields for frontend
	if riskResponse["assetName"] == nil {
		riskResponse["assetName"] = assetName
	}
	
	// Ensure risk owner name is set
	if risk.RiskOwnerName == "" {
		// Combine user's first and last name
		userName := fmt.Sprintf("%s %s", user.FirstName, user.LastName)
		if userName == " " {
			userName = user.Email
		}
		riskResponse["riskOwnerName"] = userName
	}
	
	// Add RAM fields with proper naming
	if risk.ProjectRAMCurrent != "" {
		riskResponse["projectRamCurrent"] = risk.ProjectRAMCurrent
	}
	
	if risk.ProjectRAMTarget != "" {
		riskResponse["projectRamTarget"] = risk.ProjectRAMTarget
	}
	
	if risk.RiskVisualRAMCurrent != "" {
		riskResponse["riskVisualRamCurrent"] = risk.RiskVisualRAMCurrent
	}
	
	if risk.RiskVisualRAMTarget != "" {
		riskResponse["riskVisualramTarget"] = risk.RiskVisualRAMTarget
	}
	
	if risk.HSSE_RAMCurrent != "" {
		riskResponse["hsseRamCurrent"] = risk.HSSE_RAMCurrent
	}
	
	if risk.HSSE_RAMTarget != "" {
		riskResponse["hsseRamTarget"] = risk.HSSE_RAMTarget
	}
	
	utils.RespondWithJSON(w, http.StatusOK, riskResponse)
}

// GetAnalystRiskStats returns statistics for analyst's risks
func GetAnalystRiskStats(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get analyst's assigned asset IDs
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Build base filter
	baseFilter := bson.M{"organizationId": orgID}
	assignedFilter := bson.M{"organizationId": orgID}
	
	if len(assignedAssetIDs) > 0 {
		assignedFilter["assetId"] = bson.M{"$in": assignedAssetIDs}
	} else {
		assignedFilter["createdBy"] = userID
	}
	
	// Get counts
	totalRisks, _ := riskCollection.CountDocuments(ctx, baseFilter)
	totalAssignedRisks, _ := riskCollection.CountDocuments(ctx, assignedFilter)
	
	// Risks created by analyst
	myRisksFilter := bson.M{"organizationId": orgID, "createdBy": userID}
	totalMyRisks, _ := riskCollection.CountDocuments(ctx, myRisksFilter)
	
	// High severity risks in assigned assets
	highRiskFilter := bson.M{}
	for k, v := range assignedFilter {
		highRiskFilter[k] = v
	}
	highRiskFilter["$or"] = []bson.M{
		{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
		{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
	}
	highSeverityRisks, _ := riskCollection.CountDocuments(ctx, highRiskFilter)
	
	// My pending submissions - Updated to search by title pattern
	myPendingSubmissions := int64(0)
	if len(assignedAssetIDs) > 0 {
		// Get risks created by analyst in assigned assets
		myAssignedRisksFilter := bson.M{
			"organizationId": orgID,
			"createdBy":      userID,
			"assetId":        bson.M{"$in": assignedAssetIDs},
		}
		
		cursor, err := riskCollection.Find(ctx, myAssignedRisksFilter)
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var risk models.Risk
				if err := cursor.Decode(&risk); err == nil {
					// Search for approval with matching title pattern
					approvalTitle := fmt.Sprintf("Risk Submission: %s", risk.Title)
					count, _ := approvalCollection.CountDocuments(ctx, bson.M{
						"organizationId": orgID,
						"status":         "pending",
						"title":          approvalTitle,
					})
					myPendingSubmissions += count
				}
			}
		}
	}
	
	// My approved submissions
	myApprovedSubmissions := int64(0)
	if len(assignedAssetIDs) > 0 {
		myAssignedRisksFilter := bson.M{
			"organizationId": orgID,
			"createdBy":      userID,
			"assetId":        bson.M{"$in": assignedAssetIDs},
		}
		
		cursor, err := riskCollection.Find(ctx, myAssignedRisksFilter)
		if err == nil {
			defer cursor.Close(ctx)
			for cursor.Next(ctx) {
				var risk models.Risk
				if err := cursor.Decode(&risk); err == nil {
					approvalTitle := fmt.Sprintf("Risk Submission: %s", risk.Title)
					count, _ := approvalCollection.CountDocuments(ctx, bson.M{
						"organizationId": orgID,
						"status":         "approved",
						"title":          approvalTitle,
					})
					myApprovedSubmissions += count
				}
			}
		}
	}
	
	// Status breakdown for assigned risks
	statusPipeline := []bson.M{
		{"$match": assignedFilter},
		{"$group": bson.M{
			"_id": "$status",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor, err := riskCollection.Aggregate(ctx, statusPipeline)
	statusBreakdown := make(map[string]int64)
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var result struct {
				Status string `bson:"_id"`
				Count  int64  `bson:"count"`
			}
			if err := cursor.Decode(&result); err == nil {
				statusBreakdown[result.Status] = result.Count
			}
		}
	}
	
	// Type breakdown for assigned risks
	typePipeline := []bson.M{
		{"$match": assignedFilter},
		{"$group": bson.M{
			"_id": "$type",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor2, err := riskCollection.Aggregate(ctx, typePipeline)
	typeBreakdown := make(map[string]int64)
	if err == nil {
		defer cursor2.Close(ctx)
		for cursor2.Next(ctx) {
			var result struct {
				Type  string `bson:"_id"`
				Count int64  `bson:"count"`
			}
			if err := cursor2.Decode(&result); err == nil {
				typeBreakdown[result.Type] = result.Count
			}
		}
	}
	
	// Recent activity (last 7 days)
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	recentActivity, _ := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"createdBy":      userID,
		"createdAt":      bson.M{"$gte": sevenDaysAgo},
	})
	
	// Response
	response := map[string]interface{}{
		"totalRisks":          totalRisks,
		"totalAssignedRisks":  totalAssignedRisks,
		"totalMyRisks":        totalMyRisks,
		"highSeverityRisks":   highSeverityRisks,
		"myPendingSubmissions": myPendingSubmissions,
		"myApprovedSubmissions": myApprovedSubmissions,
		"statusBreakdown":     statusBreakdown,
		"typeBreakdown":       typeBreakdown,
		"recentActivity":      recentActivity,
		"assignedAssets":      len(assignedAssetIDs),
	}
	
	utils.RespondWithJSON(w, http.StatusOK, response)
}

// GetAnalystDashboard - Returns dashboard data for analysts
func GetAnalystDashboard(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Only analysts can use this endpoint
	if user.Role != "analyst" {
		utils.RespondWithError(w, http.StatusForbidden, "Only analysts can access this dashboard")
		return
	}
	
	// Get analyst's assigned asset IDs
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Build filter for assigned risks
	riskFilter := bson.M{"organizationId": orgID}
	if len(assignedAssetIDs) > 0 {
		riskFilter["assetId"] = bson.M{"$in": assignedAssetIDs}
	} else {
		riskFilter["createdBy"] = userID
	}
	
	// Get total risks count
	totalRisks, _ := riskCollection.CountDocuments(ctx, riskFilter)
	
	// Get high severity risks
	highRiskFilter := bson.M{}
	for k, v := range riskFilter {
		highRiskFilter[k] = v
	}
	highRiskFilter["$or"] = []bson.M{
		{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
		{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
	}
	highSeverityRisks, _ := riskCollection.CountDocuments(ctx, highRiskFilter)
	
	// Get pending approval count
	riskIDs := getRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	
	pendingApprovals := int64(0)
	if len(riskIDs) > 0 {
		// Get approvals for risks in assigned assets
		for _, riskID := range riskIDs {
			var risk models.Risk
			err := riskCollection.FindOne(ctx, bson.M{"_id": riskID}).Decode(&risk)
			if err == nil {
				approvalTitle := fmt.Sprintf("Risk Submission: %s", risk.Title)
				count, _ := approvalCollection.CountDocuments(ctx, bson.M{
					"organizationId": orgID,
					"status":         "pending",
					"title":          approvalTitle,
				})
				pendingApprovals += count
			}
		}
	}
	
	// Get overdue actions
	overdueFilter := bson.M{
		"organizationId": orgID,
		"status": bson.M{"$in": []string{"open", "in-progress"}},
		"dueDate": bson.M{"$lt": time.Now()},
	}
	if len(riskIDs) > 0 {
		overdueFilter["riskId"] = bson.M{"$in": riskIDs}
	}
	overdueActions, _ := actionCollection.CountDocuments(ctx, overdueFilter)
	
	// Get recent activity (last 7 days)
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	recentActivity, _ := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"createdBy":      userID,
		"createdAt":      bson.M{"$gte": sevenDaysAgo},
	})
	
	// Response
	response := map[string]interface{}{
		"totalRisks":        totalRisks,
		"highSeverityRisks": highSeverityRisks,
		"pendingApprovals":  pendingApprovals,
		"overdueActions":    overdueActions,
		"recentActivity":    recentActivity,
		"assignedAssets":    len(assignedAssetIDs),
		"userRole":          user.Role,
		"userName":          fmt.Sprintf("%s %s", user.FirstName, user.LastName),
	}
	
	utils.RespondWithJSON(w, http.StatusOK, response)
}

// GetAnalystAssignedAssets - Returns assets assigned to the analyst
func GetAnalystAssignedAssets(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get analyst's assigned asset IDs
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Get asset details
	var assets []models.Asset
	if len(assignedAssetIDs) > 0 {
		cursor, err := assetCollection.Find(ctx, bson.M{
			"_id":            bson.M{"$in": assignedAssetIDs},
			"organizationId": orgID,
			"status":         "active",
		}, options.Find().SetSort(bson.D{{Key: "name", Value: 1}}))
		
		if err == nil {
			defer cursor.Close(ctx)
			if err = cursor.All(ctx, &assets); err != nil {
				log.Printf("Error fetching assigned assets: %v", err)
			}
		}
	}
	
	if assets == nil {
		assets = []models.Asset{}
	}
	
	utils.RespondWithJSON(w, http.StatusOK, assets)
}

// GetAnalystOverview - Returns overview statistics for analyst
func GetAnalystOverview(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get analyst's assigned asset IDs
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Build filter for assigned risks
	filter := bson.M{"organizationId": orgID}
	if len(assignedAssetIDs) > 0 {
		filter["assetId"] = bson.M{"$in": assignedAssetIDs}
	} else {
		filter["createdBy"] = userID
	}
	
	// Get status breakdown
	statusPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id": "$status",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor, err := riskCollection.Aggregate(ctx, statusPipeline)
	statusBreakdown := make(map[string]int64)
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var result struct {
				Status string `bson:"_id"`
				Count  int64  `bson:"count"`
			}
			if err := cursor.Decode(&result); err == nil {
				statusBreakdown[result.Status] = result.Count
			}
		}
	}
	
	// Get type breakdown
	typePipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id": "$type",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor2, err := riskCollection.Aggregate(ctx, typePipeline)
	typeBreakdown := make(map[string]int64)
	if err == nil {
		defer cursor2.Close(ctx)
		for cursor2.Next(ctx) {
			var result struct {
				Type  string `bson:"_id"`
				Count int64  `bson:"count"`
			}
			if err := cursor2.Decode(&result); err == nil {
				typeBreakdown[result.Type] = result.Count
			}
		}
	}
	
	// Get total counts
	totalRisks, _ := riskCollection.CountDocuments(ctx, filter)
	
	// Get risk IDs for action filtering
	riskIDs := getRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	
	// Get action counts
	openActions := int64(0)
	overdueActions := int64(0)
	if len(riskIDs) > 0 {
		openActions, _ = actionCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"riskId":         bson.M{"$in": riskIDs},
			"status":         bson.M{"$in": []string{"open", "in-progress", "on-hold"}},
		})
		
		overdueActions, _ = actionCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"riskId":         bson.M{"$in": riskIDs},
			"status":         bson.M{"$in": []string{"open", "in-progress"}},
			"dueDate":        bson.M{"$lt": time.Now()},
		})
	}
	
	// Response
	response := map[string]interface{}{
		"totalRisks":      totalRisks,
		"openActions":     openActions,
		"overdueActions":  overdueActions,
		"statusBreakdown": statusBreakdown,
		"typeBreakdown":   typeBreakdown,
		"assignedAssets":  len(assignedAssetIDs),
	}
	
	utils.RespondWithJSON(w, http.StatusOK, response)
}

// GetAnalystChartData - Returns chart data for analyst dashboard
func GetAnalystChartData(w http.ResponseWriter, r *http.Request) {
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
	
	// Get user
	userID, _ := primitive.ObjectIDFromHex(userIDHex)
	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": userID, "organizationId": orgID}).Decode(&user)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch user")
		return
	}
	
	// Get analyst's assigned asset IDs
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, user.Role)
	
	// Build filter
	filter := bson.M{"organizationId": orgID}
	if len(assignedAssetIDs) > 0 {
		filter["assetId"] = bson.M{"$in": assignedAssetIDs}
	} else {
		filter["createdBy"] = userID
	}
	
	// Get monthly trend data (last 6 months)
	now := time.Now()
	sixMonthsAgo := now.AddDate(0, -6, 0)
	
	monthlyPipeline := []bson.M{
		{"$match": bson.M{
			"organizationId": orgID,
			"createdAt": bson.M{"$gte": sixMonthsAgo},
		}},
		{"$addFields": bson.M{
			"month": bson.M{"$dateToString": bson.M{
				"format": "%Y-%m",
				"date": "$createdAt",
			}},
		}},
		{"$group": bson.M{
			"_id": "$month",
			"count": bson.M{"$sum": 1},
		}},
		{"$sort": bson.M{"_id": 1}},
	}
	
	if len(assignedAssetIDs) > 0 {
		monthlyPipeline[0]["$match"].(bson.M)["assetId"] = bson.M{"$in": assignedAssetIDs}
	} else {
		monthlyPipeline[0]["$match"].(bson.M)["createdBy"] = userID
	}
	
	cursor, err := riskCollection.Aggregate(ctx, monthlyPipeline)
	monthlyData := make(map[string]int64)
	if err == nil {
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var result struct {
				Month string `bson:"_id"`
				Count int64  `bson:"count"`
			}
			if err := cursor.Decode(&result); err == nil {
				monthlyData[result.Month] = result.Count
			}
		}
	}
	
	// Get status distribution
	statusPipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id": "$status",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor2, err := riskCollection.Aggregate(ctx, statusPipeline)
	statusData := make(map[string]int64)
	if err == nil {
		defer cursor2.Close(ctx)
		for cursor2.Next(ctx) {
			var result struct {
				Status string `bson:"_id"`
				Count  int64  `bson:"count"`
			}
			if err := cursor2.Decode(&result); err == nil {
				statusData[result.Status] = result.Count
			}
		}
	}
	
	// Get risk type distribution
	typePipeline := []bson.M{
		{"$match": filter},
		{"$group": bson.M{
			"_id": "$type",
			"count": bson.M{"$sum": 1},
		}},
	}
	
	cursor3, err := riskCollection.Aggregate(ctx, typePipeline)
	typeData := make(map[string]int64)
	if err == nil {
		defer cursor3.Close(ctx)
		for cursor3.Next(ctx) {
			var result struct {
				Type  string `bson:"_id"`
				Count int64  `bson:"count"`
			}
			if err := cursor3.Decode(&result); err == nil {
				typeData[result.Type] = result.Count
			}
		}
	}
	
	// Response
	response := map[string]interface{}{
		"monthlyTrend": monthlyData,
		"statusDistribution": statusData,
		"typeDistribution":   typeData,
	}
	
	utils.RespondWithJSON(w, http.StatusOK, response)
}

// Helper functions
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolFromMap(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
		// Also handle string "true"/"false"
		if str, ok := val.(string); ok {
			return strings.ToLower(str) == "true"
		}
	}
	return false
}
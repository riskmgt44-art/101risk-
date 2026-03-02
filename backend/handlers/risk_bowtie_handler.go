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
	"riskmgt/models"
	"riskmgt/utils"
)

// CreateRiskV2 - New endpoint for Bowtie structure
func CreateRiskV2(w http.ResponseWriter, r *http.Request) {
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
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to create risk")
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

	var req CreateRiskRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// MANDATORY VALIDATION: At least one of AssetID, SubProject, or Department must be provided
	if req.AssetID == "" && req.SubProject == "" && req.Department == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Either assetId, subProject, or department must be provided")
		return
	}

	// Validate required fields
	if req.Title == "" || len(req.Title) > 200 {
		utils.RespondWithError(w, http.StatusBadRequest, "Title is required and must be less than 200 characters")
		return
	}
	if req.Description == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Description is required")
		return
	}
	if req.Type == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Type is required")
		return
	}
	if req.Status == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Status is required")
		return
	}

	var assetID primitive.ObjectID
	if req.AssetID != "" {
		assetID, err = primitive.ObjectIDFromHex(req.AssetID)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id")
			return
		}
		
		// Verify asset exists
		assetCount, err := assetCollection.CountDocuments(r.Context(), bson.M{
			"_id":            assetID,
			"organizationId": orgID,
		})
		if err != nil || assetCount == 0 {
			utils.RespondWithError(w, http.StatusBadRequest, "asset not found")
			return
		}
	}

	// Generate risk ID
	riskID := generateRiskID()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Parse dates with error handling
	nextReviewDate, err := parseDatePointer(req.NextReviewDate)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("nextReviewDate: %v", err))
		return
	}
	
	exposureStartDate, err := parseDatePointer(req.ExposureStartDate)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("exposureStartDate: %v", err))
		return
	}
	
	exposureEndDate, err := parseDatePointer(req.ExposureEndDate)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("exposureEndDate: %v", err))
		return
	}

	// Validate exposure dates
	if exposureStartDate != nil && exposureEndDate != nil {
		if exposureEndDate.Before(*exposureStartDate) {
			utils.RespondWithError(w, http.StatusBadRequest, "exposureEndDate must be after exposureStartDate")
			return
		}
	}

	// Parse Bowtie structures
	bowtieCauses := make([]models.Cause, 0)
	for _, causeReq := range req.BowtieCauses {
		// Validate cause
		if causeReq.Title == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Cause title is required")
			return
		}

		cause := models.Cause{
			ID:          primitive.NewObjectID(),
			Title:       causeReq.Title,
			Description: causeReq.Description,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		
		// Parse actions for this cause
		for _, actionReq := range causeReq.Actions {
			// Validate action
			if actionReq.Title == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
				return
			}
			if actionReq.Type == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action type is required")
				return
			}
			if actionReq.Owner == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action owner is required")
				return
			}

			var dueDate *time.Time
			if actionReq.DueDate != nil {
				parsedDate, err := time.Parse("2006-01-02", *actionReq.DueDate)
				if err == nil {
					dueDate = &parsedDate
				}
			}
			
			action := models.RiskAction{
				ID:           primitive.NewObjectID(),
				Title:        actionReq.Title,
				Description:  actionReq.Description,
				Type:         actionReq.Type,
				Owner:        actionReq.Owner,
				DueDate:      dueDate,
				Status:       actionReq.Status,
				Priority:     actionReq.Priority,
				Cost:         actionReq.Cost,
				Effectiveness: actionReq.Effectiveness,
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
			}
			cause.Actions = append(cause.Actions, action)
		}
		bowtieCauses = append(bowtieCauses, cause)
	}

	// Parse consequences
	bowtieConsequences := make([]models.Consequence, 0)
	for _, consReq := range req.BowtieConsequences {
		// Validate consequence
		if consReq.Title == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Consequence title is required")
			return
		}

		consequence := models.Consequence{
			ID:          primitive.NewObjectID(),
			Title:       consReq.Title,
			Description: consReq.Description,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		
		// Parse actions for this consequence
		for _, actionReq := range consReq.Actions {
			// Validate action
			if actionReq.Title == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
				return
			}
			if actionReq.Type == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action type is required")
				return
			}
			if actionReq.Owner == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action owner is required")
				return
			}

			var dueDate *time.Time
			if actionReq.DueDate != nil {
				parsedDate, err := time.Parse("2006-01-02", *actionReq.DueDate)
				if err == nil {
					dueDate = &parsedDate
				}
			}
			
			action := models.RiskAction{
				ID:           primitive.NewObjectID(),
				Title:        actionReq.Title,
				Description:  actionReq.Description,
				Type:         actionReq.Type,
				Owner:        actionReq.Owner,
				DueDate:      dueDate,
				Status:       actionReq.Status,
				Priority:     actionReq.Priority,
				Cost:         actionReq.Cost,
				Effectiveness: actionReq.Effectiveness,
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
			}
			consequence.Actions = append(consequence.Actions, action)
		}
		bowtieConsequences = append(bowtieConsequences, consequence)
	}

	// Calculate risk score if likelihood and impact provided
	riskScore := 0.0
	if req.Likelihood != "" && req.Impact != "" {
		// Convert likelihood and impact to numerical values
		likelihoodMap := map[string]float64{
			"rare": 1, "unlikely": 2, "possible": 3, "likely": 4, "almost_certain": 5,
			"1": 1, "2": 2, "3": 3, "4": 4, "5": 5,
			"low": 1, "medium": 3, "high": 5,
		}
		impactMap := map[string]float64{
			"insignificant": 1, "minor": 2, "moderate": 3, "major": 4, "catastrophic": 5,
			"1": 1, "2": 2, "3": 3, "4": 4, "5": 5,
			"low": 1, "medium": 3, "high": 5,
		}
		
		if l, ok := likelihoodMap[strings.ToLower(req.Likelihood)]; ok {
			if i, ok := impactMap[strings.ToLower(req.Impact)]; ok {
				riskScore = l * i
			}
		}
	}

	risk := models.Risk{
		ID:                    primitive.NewObjectID(),
		OrganizationID:        orgID,
		RiskID:                riskID,
		Title:                 req.Title,
		Description:           req.Description,
		Type:                  req.Type,
		
		// Asset/Sub-project/Department linkage
		AssetID:               assetID,
		SubProject:            req.SubProject,
		Department:           req.Department,
		
		// Bowtie structure
		BowtieCauses:         bowtieCauses,
		BowtieConsequences:   bowtieConsequences,
		
		// For backward compatibility
		Causes:               req.Causes,
		Consequences:         req.Consequences,
		
		// Risk assessment
		Likelihood:           req.Likelihood,
		Impact:               req.Impact,
		RiskScore:            riskScore,
		
		// Other fields
		Status:                req.Status,
		RiskOwnerName:         req.RiskOwnerName,
		NextReviewDate:        nextReviewDate,
		ExposureStartDate:     exposureStartDate,
		ExposureEndDate:       exposureEndDate,
		OccurenceLevel:        req.OccurrenceLevel,
		AuditTrailCount:       1,
		LinkedActions:         []string{},
		ProjectRAMCurrent:     req.ProjectRAMCurrent,
		ProjectRAMTarget:      req.ProjectRAMTarget,
		RiskVisualRAMCurrent:  req.RiskVisualRAMCurrent,
		RiskVisualRAMTarget:   req.RiskVisualRAMTarget,
		HSSE_RAMCurrent:       req.HSSE_RAMCurrent,
		HSSE_RAMTarget:        req.HSSE_RAMTarget,
		Manageability:         req.Manageability,
		FunctionalAreaTECOP:   req.FunctionalAreaTECOP,
		ThresholdChanging:     req.ThresholdChanging,
		CreatedBy:             userID,
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}

	_, err = riskCollection.InsertOne(ctx, risk)
	if err != nil {
		log.Printf("insert risk error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to create risk")
		return
	}

	// Audit
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "risk_create_bowtie",
		EntityType:     "risk",
		EntityID:       risk.ID,
		Details:        bson.M{"title": req.Title, "type": req.Type, "riskId": riskID, "bowtie": true},
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusCreated, risk)
}

// CreateAnalystRiskV2 - New endpoint for analysts with Bowtie structure
func CreateAnalystRiskV2(w http.ResponseWriter, r *http.Request) {
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
	
	var req AnalystCreateRiskRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid payload")
		return
	}
	
	// Validate required fields
	if req.Title == "" || len(req.Title) > 200 {
		utils.RespondWithError(w, http.StatusBadRequest, "Title is required and must be less than 200 characters")
		return
	}
	if req.Description == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Description is required")
		return
	}
	if req.Type == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Type is required")
		return
	}
	if req.OccurrenceLevel == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Occurrence level is required")
		return
	}
	
	// MANDATORY VALIDATION: At least one of AssetID or SubProject must be provided
	if req.AssetID == "" && req.SubProject == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "Either assetId or subProject must be provided")
		return
	}
	
	// Validate asset ID if provided
	var assetID primitive.ObjectID
	if req.AssetID != "" {
		assetID, err = primitive.ObjectIDFromHex(req.AssetID)
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
	nextReviewDate, err := parseDatePointer(req.NextReviewDate)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("nextReviewDate: %v", err))
		return
	}
	
	exposureStartDate, err := parseDatePointer(req.ExposureStartDate)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("exposureStartDate: %v", err))
		return
	}
	
	exposureEndDate, err := parseDatePointer(req.ExposureEndDate)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("exposureEndDate: %v", err))
		return
	}
	
	// Validate exposure dates
	if exposureStartDate != nil && exposureEndDate != nil {
		if exposureEndDate.Before(*exposureStartDate) {
			utils.RespondWithError(w, http.StatusBadRequest, "exposureEndDate must be after exposureStartDate")
			return
		}
	}
	
	// Parse Bowtie structures
	bowtieCauses := make([]models.Cause, 0)
	for _, causeReq := range req.BowtieCauses {
		if causeReq.Title == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Cause title is required")
			return
		}

		cause := models.Cause{
			ID:          primitive.NewObjectID(),
			Title:       causeReq.Title,
			Description: causeReq.Description,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		
		for _, actionReq := range causeReq.Actions {
			if actionReq.Title == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
				return
			}
			if actionReq.Type == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action type is required")
				return
			}
			if actionReq.Owner == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action owner is required")
				return
			}

			var dueDate *time.Time
			if actionReq.DueDate != nil {
				parsedDate, err := time.Parse("2006-01-02", *actionReq.DueDate)
				if err == nil {
					dueDate = &parsedDate
				}
			}
			
			action := models.RiskAction{
				ID:           primitive.NewObjectID(),
				Title:        actionReq.Title,
				Description:  actionReq.Description,
				Type:         actionReq.Type,
				Owner:        actionReq.Owner,
				DueDate:      dueDate,
				Status:       actionReq.Status,
				Priority:     actionReq.Priority,
				Cost:         actionReq.Cost,
				Effectiveness: actionReq.Effectiveness,
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
			}
			cause.Actions = append(cause.Actions, action)
		}
		bowtieCauses = append(bowtieCauses, cause)
	}

	bowtieConsequences := make([]models.Consequence, 0)
	for _, consReq := range req.BowtieConsequences {
		if consReq.Title == "" {
			utils.RespondWithError(w, http.StatusBadRequest, "Consequence title is required")
			return
		}

		consequence := models.Consequence{
			ID:          primitive.NewObjectID(),
			Title:       consReq.Title,
			Description: consReq.Description,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}
		
		for _, actionReq := range consReq.Actions {
			if actionReq.Title == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
				return
			}
			if actionReq.Type == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action type is required")
				return
			}
			if actionReq.Owner == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Action owner is required")
				return
			}

			var dueDate *time.Time
			if actionReq.DueDate != nil {
				parsedDate, err := time.Parse("2006-01-02", *actionReq.DueDate)
				if err == nil {
					dueDate = &parsedDate
				}
			}
			
			action := models.RiskAction{
				ID:           primitive.NewObjectID(),
				Title:        actionReq.Title,
				Description:  actionReq.Description,
				Type:         actionReq.Type,
				Owner:        actionReq.Owner,
				DueDate:      dueDate,
				Status:       actionReq.Status,
				Priority:     actionReq.Priority,
				Cost:         actionReq.Cost,
				Effectiveness: actionReq.Effectiveness,
				CreatedAt:    time.Now().UTC(),
				UpdatedAt:    time.Now().UTC(),
			}
			consequence.Actions = append(consequence.Actions, action)
		}
		bowtieConsequences = append(bowtieConsequences, consequence)
	}
	
	// Generate risk ID
	riskID := generateRiskID()
	
	// Create risk with "pending" status (requires approval)
	risk := models.Risk{
		ID:                    primitive.NewObjectID(),
		OrganizationID:        orgID,
		RiskID:                riskID,
		Title:                 req.Title,
		Description:           req.Description,
		Type:                  req.Type,
		
		// Asset/Sub-project linkage
		AssetID:               assetID,
		SubProject:            req.SubProject,
		
		// Bowtie structure
		BowtieCauses:         bowtieCauses,
		BowtieConsequences:   bowtieConsequences,
		
		// For backward compatibility
		Causes:               req.Causes,
		Consequences:         req.Consequences,
		
		// Analyst specific
		Status:                "pending",
		RiskOwnerName:         req.RiskOwnerName,
		NextReviewDate:        nextReviewDate,
		ExposureStartDate:     exposureStartDate,
		ExposureEndDate:       exposureEndDate,
		OccurenceLevel:        req.OccurrenceLevel,
		LinkedAssets:          []string{},
		AuditTrailCount:       1,
		LinkedActions:         []string{},
		ProjectRAMCurrent:     req.ProjectRAMCurrent,
		ProjectRAMTarget:      req.ProjectRAMTarget,
		RiskVisualRAMCurrent:  req.RiskVisualRAMCurrent,
		RiskVisualRAMTarget:   req.RiskVisualRAMTarget,
		HSSE_RAMCurrent:       req.HSSE_RAMCurrent,
		HSSE_RAMTarget:        req.HSSE_RAMTarget,
		Manageability:         req.Manageability,
		FunctionalAreaTECOP:   req.FunctionalAreaTECOP,
		ThresholdChanging:     req.ThresholdChanging,
		CreatedBy:             userID,
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}
	
	// Insert risk
	_, err = riskCollection.InsertOne(ctx, risk)
	if err != nil {
		log.Printf("Error creating analyst risk: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create risk")
		return
	}
	
	// Create approval request
	userObjectID, _ := primitive.ObjectIDFromHex(userIDHex)
	approval := models.Approval{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		Title:          fmt.Sprintf("Risk Submission: %s", risk.Title),
		Type:           "risk_submission",
		Status:         "pending",
		SubmittedBy:    userObjectID,
		SubmittedAt:    time.Now().UTC(),
		CurrentLevel:   1,
		TotalLevels:    1,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	
	_, err = approvalCollection.InsertOne(ctx, approval)
	if err != nil {
		log.Printf("Failed to create approval request: %v", err)
		// Continue even if approval creation fails
	}
	
	// Create audit log
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		UserEmail:      r.Context().Value("userName").(string),
		UserRole:       user.Role,
		Action:         "analyst_risk_create_bowtie",
		EntityType:     "risk",
		EntityID:       risk.ID,
		Details:        bson.M{"title": req.Title, "type": req.Type, "riskId": riskID, "status": "pending", "bowtie": true},
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
		"risk":     risk,
		"approval": map[string]interface{}{"id": approval.ID, "status": "pending", "title": approval.Title},
	})
}

// GetRiskBowtieView returns risk with Bowtie structure
func GetRiskBowtieView(w http.ResponseWriter, r *http.Request) {
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

	// Get ID from path parameter
	vars := mux.Vars(r)
	riskIDStr := vars["id"]
	if riskIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "risk id required")
		return
	}

	riskID, err := primitive.ObjectIDFromHex(riskIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid risk id format")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var risk models.Risk
	err = riskCollection.FindOne(ctx, bson.M{"_id": riskID, "organizationId": orgID}).Decode(&risk)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "risk not found")
			return
		}
		log.Printf("find risk error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}

	// Calculate total actions for summary
	totalActions := 0
	preventiveActions := 0
	mitigativeActions := 0
	
	for _, cause := range risk.BowtieCauses {
		totalActions += len(cause.Actions)
		for _, action := range cause.Actions {
			if action.Type == "preventive" || action.Type == "detective" {
				preventiveActions++
			}
		}
	}
	
	for _, consequence := range risk.BowtieConsequences {
		totalActions += len(consequence.Actions)
		for _, action := range consequence.Actions {
			if action.Type == "mitigative" || action.Type == "recovery" {
				mitigativeActions++
			}
		}
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"risk":            risk,
		"bowtieView":      true,
		"totalCauses":     len(risk.BowtieCauses),
		"totalConsequences": len(risk.BowtieConsequences),
		"totalActions":    totalActions,
		"preventiveActions": preventiveActions,
		"mitigativeActions": mitigativeActions,
	})
}

// UpdateRiskV2 - Update risk with Bowtie structure
func UpdateRiskV2(w http.ResponseWriter, r *http.Request) {
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
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to update risk")
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

	// Get ID from path parameter
	vars := mux.Vars(r)
	riskIDStr := vars["id"]
	if riskIDStr == "" {
		utils.RespondWithError(w, http.StatusBadRequest, "risk id required")
		return
	}

	riskID, err := primitive.ObjectIDFromHex(riskIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid risk id format")
		return
	}

	var req UpdateRiskRequestV2
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// First, get the existing risk
	var existingRisk models.Risk
	err = riskCollection.FindOne(ctx, bson.M{"_id": riskID, "organizationId": orgID}).Decode(&existingRisk)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "risk not found")
			return
		}
		log.Printf("find risk error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database query failed")
		return
	}

	update := bson.M{}
	
	// Helper to add field if provided
	addField := func(fieldName string, value interface{}) {
		if value != nil && value != "" {
			update[fieldName] = value
		}
	}

	addField("title", req.Title)
	addField("description", req.Description)
	addField("type", req.Type)
	addField("riskOwnerName", req.RiskOwnerName)
	addField("subProject", req.SubProject)
	addField("department", req.Department)
	addField("occurrenceLevel", req.OccurrenceLevel)
	addField("likelihood", req.Likelihood)
	addField("impact", req.Impact)
	addField("projectRamCurrent", req.ProjectRAMCurrent)
	addField("projectRamTarget", req.ProjectRAMTarget)
	addField("riskVisualRamCurrent", req.RiskVisualRAMCurrent)
	addField("riskVisualRamTarget", req.RiskVisualRAMTarget)
	addField("hsseRamCurrent", req.HSSE_RAMCurrent)
	addField("hsseRamTarget", req.HSSE_RAMTarget)
	addField("manageability", req.Manageability)
	addField("functionalAreaTECOP", req.FunctionalAreaTECOP)
	
	// Handle old fields for backward compatibility
	if req.Causes != nil {
		update["causes"] = req.Causes
	}
	if req.Consequences != nil {
		update["consequences"] = req.Consequences
	}
	if req.LinkedAssets != nil {
		update["linkedAssets"] = req.LinkedAssets
	}
	if req.LinkedActions != nil {
		update["linkedActions"] = req.LinkedActions
	}
	if req.Status != "" {
		update["status"] = req.Status
	}
	if req.ThresholdChanging != nil {
		update["thresholdChanging"] = *req.ThresholdChanging
	}

	// Parse and validate dates
	if req.NextReviewDate != nil {
		nextReviewDate, err := parseDatePointer(req.NextReviewDate)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("nextReviewDate: %v", err))
			return
		}
		update["nextReviewDate"] = nextReviewDate
	}
	
	if req.ExposureStartDate != nil {
		exposureStartDate, err := parseDatePointer(req.ExposureStartDate)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("exposureStartDate: %v", err))
			return
		}
		update["exposureStartDate"] = exposureStartDate
	}
	
	if req.ExposureEndDate != nil {
		exposureEndDate, err := parseDatePointer(req.ExposureEndDate)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, fmt.Sprintf("exposureEndDate: %v", err))
			return
		}
		update["exposureEndDate"] = exposureEndDate
	}

	// Handle asset ID update
	if req.AssetID != "" {
		assetID, err := primitive.ObjectIDFromHex(req.AssetID)
		if err != nil {
			utils.RespondWithError(w, http.StatusBadRequest, "invalid asset id")
			return
		}
		
		// Verify asset exists
		assetCount, err := assetCollection.CountDocuments(ctx, bson.M{
			"_id":            assetID,
			"organizationId": orgID,
		})
		if err != nil || assetCount == 0 {
			utils.RespondWithError(w, http.StatusBadRequest, "asset not found")
			return
		}
		update["assetId"] = assetID
	}

	// Handle Bowtie structure update if provided
	if len(req.BowtieCauses) > 0 {
		bowtieCauses := make([]models.Cause, 0)
		for _, causeReq := range req.BowtieCauses {
			if causeReq.Title == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Cause title is required")
				return
			}

			cause := models.Cause{
				ID:          primitive.NewObjectID(),
				Title:       causeReq.Title,
				Description: causeReq.Description,
				CreatedAt:   time.Now().UTC(),
				UpdatedAt:   time.Now().UTC(),
			}
			
			for _, actionReq := range causeReq.Actions {
				if actionReq.Title == "" {
					utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
					return
				}
				if actionReq.Type == "" {
					utils.RespondWithError(w, http.StatusBadRequest, "Action type is required")
					return
				}
				if actionReq.Owner == "" {
					utils.RespondWithError(w, http.StatusBadRequest, "Action owner is required")
					return
				}

				var dueDate *time.Time
				if actionReq.DueDate != nil {
					parsedDate, err := time.Parse("2006-01-02", *actionReq.DueDate)
					if err == nil {
						dueDate = &parsedDate
					}
				}
				
				action := models.RiskAction{
					ID:           primitive.NewObjectID(),
					Title:        actionReq.Title,
					Description:  actionReq.Description,
					Type:         actionReq.Type,
					Owner:        actionReq.Owner,
					DueDate:      dueDate,
					Status:       actionReq.Status,
					Priority:     actionReq.Priority,
					Cost:         actionReq.Cost,
					Effectiveness: actionReq.Effectiveness,
					CreatedAt:    time.Now().UTC(),
					UpdatedAt:    time.Now().UTC(),
				}
				cause.Actions = append(cause.Actions, action)
			}
			bowtieCauses = append(bowtieCauses, cause)
		}
		update["bowtieCauses"] = bowtieCauses
	}

	if len(req.BowtieConsequences) > 0 {
		bowtieConsequences := make([]models.Consequence, 0)
		for _, consReq := range req.BowtieConsequences {
			if consReq.Title == "" {
				utils.RespondWithError(w, http.StatusBadRequest, "Consequence title is required")
				return
			}

			consequence := models.Consequence{
				ID:          primitive.NewObjectID(),
				Title:       consReq.Title,
				Description: consReq.Description,
				CreatedAt:   time.Now().UTC(),
				UpdatedAt:   time.Now().UTC(),
			}
			
			for _, actionReq := range consReq.Actions {
				if actionReq.Title == "" {
					utils.RespondWithError(w, http.StatusBadRequest, "Action title is required")
					return
				}
				if actionReq.Type == "" {
					utils.RespondWithError(w, http.StatusBadRequest, "Action type is required")
					return
				}
				if actionReq.Owner == "" {
					utils.RespondWithError(w, http.StatusBadRequest, "Action owner is required")
					return
				}

				var dueDate *time.Time
				if actionReq.DueDate != nil {
					parsedDate, err := time.Parse("2006-01-02", *actionReq.DueDate)
					if err == nil {
						dueDate = &parsedDate
					}
				}
				
				action := models.RiskAction{
					ID:           primitive.NewObjectID(),
					Title:        actionReq.Title,
					Description:  actionReq.Description,
					Type:         actionReq.Type,
					Owner:        actionReq.Owner,
					DueDate:      dueDate,
					Status:       actionReq.Status,
					Priority:     actionReq.Priority,
					Cost:         actionReq.Cost,
					Effectiveness: actionReq.Effectiveness,
					CreatedAt:    time.Now().UTC(),
					UpdatedAt:    time.Now().UTC(),
				}
				consequence.Actions = append(consequence.Actions, action)
			}
			bowtieConsequences = append(bowtieConsequences, consequence)
		}
		update["bowtieConsequences"] = bowtieConsequences
	}

	// Calculate risk score if likelihood and impact provided
	if req.Likelihood != "" && req.Impact != "" {
		likelihoodMap := map[string]float64{
			"rare": 1, "unlikely": 2, "possible": 3, "likely": 4, "almost_certain": 5,
			"1": 1, "2": 2, "3": 3, "4": 4, "5": 5,
			"low": 1, "medium": 3, "high": 5,
		}
		impactMap := map[string]float64{
			"insignificant": 1, "minor": 2, "moderate": 3, "major": 4, "catastrophic": 5,
			"1": 1, "2": 2, "3": 3, "4": 4, "5": 5,
			"low": 1, "medium": 3, "high": 5,
		}
		
		riskScore := 0.0
		if l, ok := likelihoodMap[strings.ToLower(req.Likelihood)]; ok {
			if i, ok := impactMap[strings.ToLower(req.Impact)]; ok {
				riskScore = l * i
			}
		}
		update["riskScore"] = riskScore
	}

	update["updatedAt"] = time.Now().UTC()
	update["updatedBy"] = userID

	if len(update) == 0 {
		utils.RespondWithError(w, http.StatusBadRequest, "no fields to update")
		return
	}

	// Prepare update operation
	updateSet := bson.M{"$set": update}
	updateSet["$inc"] = bson.M{"auditTrailCount": 1}

	result, err := riskCollection.UpdateOne(ctx, bson.M{"_id": riskID, "organizationId": orgID}, updateSet)
	if err != nil {
		log.Printf("update risk error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to update risk")
		return
	}
	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "risk not found")
		return
	}

	// Get updated risk to return
	var updatedRisk models.Risk
	err = riskCollection.FindOne(ctx, bson.M{"_id": riskID}).Decode(&updatedRisk)
	if err != nil {
		log.Printf("find updated risk error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch updated risk")
		return
	}

	// Audit
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "risk_update_bowtie",
		EntityType:     "risk",
		EntityID:       riskID,
		Details:        bson.M{"bowtie": true},
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, updatedRisk)
}
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
// RiskRequest validation helper
type RiskValidator struct{}

func (v *RiskValidator) ValidateCreate(req CreateRiskRequest) error {
	if req.Title == "" || len(req.Title) > 200 {
		return fmt.Errorf("title is required and must be less than 200 characters")
	}
	if req.Description == "" {
		return fmt.Errorf("description is required")
	}
	if req.Type == "" {
		return fmt.Errorf("type is required")
	}
	if req.Status == "" {
		return fmt.Errorf("status is required")
	}
	return nil
}

func (v *RiskValidator) ValidateUpdate(req UpdateRiskRequest) error {
	if req.Title != "" && len(req.Title) > 200 {
		return fmt.Errorf("title must be less than 200 characters")
	}
	return nil
}

// Helper function to parse date pointers safely
func parseDatePointer(dateStr *string) (*time.Time, error) {
	if dateStr == nil || *dateStr == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", *dateStr)
	if err != nil {
		return nil, fmt.Errorf("invalid date format, expected YYYY-MM-DD")
	}
	return &t, nil
}

// Helper function to generate unique risk ID
func generateRiskID() string {
	timestamp := time.Now().Format("20060102")
	randomNum, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return fmt.Sprintf("RISK-%s-%04d", timestamp, randomNum.Int64())
}

// Common helper function for calculating start dates (moved from line 831 and heatmap.go line 353)
func calculateStartDateForRisk(timeRange string) time.Time {
	now := time.Now()
	switch timeRange {
	case "7d", "7":
		return now.AddDate(0, 0, -7)
	case "30d", "30":
		return now.AddDate(0, 0, -30)
	case "90d", "90":
		return now.AddDate(0, 0, -90)
	case "180d", "180":
		return now.AddDate(0, 0, -180)
	case "ytd":
		return time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
	case "1y":
		return now.AddDate(-1, 0, 0)
	case "2y":
		return now.AddDate(-2, 0, 0)
	default:
		return time.Time{} // zero time
	}
}

func ListRisks(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	filter := bson.M{"organizationId": orgID}

	// Get filter parameters
	status := r.URL.Query().Get("status")
	typeFilter := r.URL.Query().Get("type")
	
	if status != "" {
		filter["status"] = status
	}
	if typeFilter != "" {
		filter["type"] = typeFilter
	}

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

	log.Printf("returned %d risks for org %s", len(risks), orgIDStr)
	utils.RespondWithJSON(w, http.StatusOK, risks)
}

type CreateRiskRequest struct {
	Title                 string   `json:"title"`
	Description           string   `json:"description"`
	Type                  string   `json:"type"`
	AssetID               string   `json:"assetId,omitempty"`
	Status                string   `json:"status"`
	Causes                []string `json:"causes,omitempty"`
	Event                 string   `json:"event,omitempty"`
	Consequences          []string `json:"consequences,omitempty"`
	RiskOwnerName         string   `json:"riskOwnerName,omitempty"`
	SubProject            string   `json:"subProject,omitempty"`
	NextReviewDate        *string  `json:"nextReviewDate,omitempty"`
	ExposureStartDate     *string  `json:"exposureStartDate,omitempty"`
	ExposureEndDate       *string  `json:"exposureEndDate,omitempty"`
	OccurenceLevel        string   `json:"occurenceLevel,omitempty"`
	LinkedAssets          []string `json:"linkedAssets,omitempty"`
	ProjectRAMCurrent     string   `json:"projectRamCurrent,omitempty"`
	ProjectRAMTarget      string   `json:"projectRamTarget,omitempty"`
	RiskVisualRAMCurrent  string   `json:"riskVisualRamCurrent,omitempty"`
	RiskVisualRAMTarget   string   `json:"riskVisualRamTarget,omitempty"`
	HSSE_RAMCurrent       string   `json:"hsseRamCurrent,omitempty"`
	HSSE_RAMTarget        string   `json:"hsseRamTarget,omitempty"`
	Manageability         string   `json:"manageability,omitempty"`
	FunctionalAreaTECOP   string   `json:"functionalAreaTECOP,omitempty"`
	ThresholdChanging     bool     `json:"thresholdChanging"`
}

func CreateRisk(w http.ResponseWriter, r *http.Request) {
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

	var req CreateRiskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Validate request
	validator := RiskValidator{}
	if err := validator.ValidateCreate(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error())
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

	risk := models.Risk{
		ID:                    primitive.NewObjectID(),
		OrganizationID:        orgID,
		RiskID:                riskID,
		Title:                 req.Title,
		Description:           req.Description,
		Type:                  req.Type,
		Causes:                req.Causes,
		Event:                 req.Event,
		Consequences:          req.Consequences,
		Status:                req.Status,
		RiskOwnerName:         req.RiskOwnerName,
		SubProject:            req.SubProject,
		NextReviewDate:        nextReviewDate,
		ExposureStartDate:     exposureStartDate,
		ExposureEndDate:       exposureEndDate,
		OccurenceLevel:        req.OccurenceLevel,
		AssetID:               assetID,
		LinkedAssets:          req.LinkedAssets,
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
		Action:         "risk_create",
		EntityType:     "risk",
		EntityID:       risk.ID,
		Details:        bson.M{"title": req.Title, "type": req.Type, "riskId": riskID},
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusCreated, risk)
}

func GetRisk(w http.ResponseWriter, r *http.Request) {
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

	utils.RespondWithJSON(w, http.StatusOK, risk)
}

type UpdateRiskRequest struct {
	Title                 string   `json:"title,omitempty"`
	Description           string   `json:"description,omitempty"`
	Type                  string   `json:"type,omitempty"`
	Causes                []string `json:"causes,omitempty"`
	Event                 string   `json:"event,omitempty"`
	Consequences          []string `json:"consequences,omitempty"`
	Status                string   `json:"status,omitempty"`
	RiskOwnerName         string   `json:"riskOwnerName,omitempty"`
	SubProject            string   `json:"subProject,omitempty"`
	NextReviewDate        *string  `json:"nextReviewDate,omitempty"`
	ExposureStartDate     *string  `json:"exposureStartDate,omitempty"`
	ExposureEndDate       *string  `json:"exposureEndDate,omitempty"`
	OccurenceLevel        string   `json:"occurenceLevel,omitempty"`
	AssetID               string   `json:"assetId,omitempty"`
	LinkedAssets          []string `json:"linkedAssets,omitempty"`
	LinkedActions         []string `json:"linkedActions,omitempty"`
	ProjectRAMCurrent     string   `json:"projectRamCurrent,omitempty"`
	ProjectRAMTarget      string   `json:"projectRamTarget,omitempty"`
	RiskVisualRAMCurrent  string   `json:"riskVisualRamCurrent,omitempty"`
	RiskVisualRAMTarget   string   `json:"riskVisualRamTarget,omitempty"`
	HSSE_RAMCurrent       string   `json:"hsseRamCurrent,omitempty"`
	HSSE_RAMTarget        string   `json:"hsseRamTarget,omitempty"`
	Manageability         string   `json:"manageability,omitempty"`
	FunctionalAreaTECOP   string   `json:"functionalAreaTECOP,omitempty"`
	ThresholdChanging     *bool    `json:"thresholdChanging,omitempty"`
}

func UpdateRisk(w http.ResponseWriter, r *http.Request) {
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

	var req UpdateRiskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	// Validate request
	validator := RiskValidator{}
	if err := validator.ValidateUpdate(req); err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// First, get the existing risk to preserve some fields
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
	addField("event", req.Event)
	addField("riskOwnerName", req.RiskOwnerName)
	addField("subProject", req.SubProject)
	addField("occurenceLevel", req.OccurenceLevel)
	addField("projectRamCurrent", req.ProjectRAMCurrent)
	addField("projectRamTarget", req.ProjectRAMTarget)
	addField("riskVisualRamCurrent", req.RiskVisualRAMCurrent)
	addField("riskVisualRamTarget", req.RiskVisualRAMTarget)
	addField("hsseRamCurrent", req.HSSE_RAMCurrent)
	addField("hsseRamTarget", req.HSSE_RAMTarget)
	addField("manageability", req.Manageability)
	addField("functionalAreaTECOP", req.FunctionalAreaTECOP)
	
	if req.Causes != nil {
		update["causes"] = req.Causes
	}
	if req.Consequences != nil {
		update["consequences"] = req.Consequences
	}
	if req.Status != "" {
		update["status"] = req.Status
	}
	if req.LinkedAssets != nil {
		update["linkedAssets"] = req.LinkedAssets
	}
	if req.LinkedActions != nil {
		update["linkedActions"] = req.LinkedActions
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
		Action:         "risk_update",
		EntityType:     "risk",
		EntityID:       riskID,
		Details:        update,
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, updatedRisk)
}

func DeleteRisk(w http.ResponseWriter, r *http.Request) {
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
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions to delete risk")
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check if linked to actions
	actionCount, err := actionCollection.CountDocuments(ctx, bson.M{"riskId": riskID})
	if err != nil {
		log.Printf("check linked actions error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "database error")
		return
	}
	
	// If there are linked actions, check if user has permission to delete anyway
	if actionCount > 0 {
		// Only superadmin can delete risks with linked actions
		if role != "superadmin" {
			utils.RespondWithError(w, http.StatusForbidden, 
				"risk is linked to actions. Only superadmin can delete risks with linked actions")
			return
		}
		
		// Optionally, we could delete the linked actions first
		// For now, just proceed with deletion
		log.Printf("Superadmin deleting risk %s with %d linked actions", riskIDStr, actionCount)
	}

	// Get risk details for audit log before deletion
	var risk models.Risk
	err = riskCollection.FindOne(ctx, bson.M{"_id": riskID, "organizationId": orgID}).Decode(&risk)
	if err != nil && err != mongo.ErrNoDocuments {
		log.Printf("find risk for audit error: %v", err)
	}

	result, err := riskCollection.DeleteOne(ctx, bson.M{"_id": riskID, "organizationId": orgID})
	if err != nil {
		log.Printf("delete risk error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to delete risk")
		return
	}
	if result.DeletedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "risk not found")
		return
	}

	// Audit
	auditDetails := bson.M{
		"riskId":  risk.RiskID,
		"title":   risk.Title,
		"actions": actionCount,
	}
	
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "risk_delete",
		EntityType:     "risk",
		EntityID:       riskID,
		Details:        auditDetails,
		CreatedAt:      time.Now().UTC(),
	}
	
	if _, err := auditLogCollection.InsertOne(ctx, audit); err != nil {
		log.Printf("Failed to create audit log: %v", err)
	}
	
	BroadcastAudit(&audit)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":      "risk deleted successfully",
		"riskId":       riskID.Hex(),
		"linkedActions": actionCount,
	})
}
// Add this function to your handlers/risks.go file (before the closing brace)
func GetFilteredRisks(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Build filter from query parameters
	filter := bson.M{
		"organizationId": orgID,
		"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	}

	// Apply filters from query parameters
	query := r.URL.Query()
	
	if department := query.Get("department"); department != "" {
		filter["department"] = department
	}
	
	if category := query.Get("category"); category != "" {
		filter["category"] = category
	}
	
	if region := query.Get("region"); region != "" {
		filter["region"] = region
	}
	
	if businessUnit := query.Get("businessUnit"); businessUnit != "" && businessUnit != "all" {
		filter["businessUnit"] = businessUnit
	}
	
	if riskOwner := query.Get("riskOwner"); riskOwner != "" && riskOwner != "all" {
		if riskOwner == "unassigned" {
			filter["owner"] = bson.M{"$in": []interface{}{"", nil}}
		}
	}

	// Apply time range filter if provided
	if timeRange := query.Get("timeRange"); timeRange != "" {
		startDate := calculateStartDateForRisk(timeRange)
		if !startDate.IsZero() {
			filter["createdAt"] = bson.M{"$gte": startDate}
		}
	}

	// Apply severity filter
	if severity := query.Get("severity"); severity != "" && severity != "all" {
		switch severity {
		case "high":
			filter["$or"] = []bson.M{
				{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
				{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
			}
		case "medium":
			filter["$or"] = []bson.M{
				{"impactLevel": bson.M{"$in": []string{"Medium", "High", "Extreme", "3", "4", "5"}}},
				{"likelihoodLevel": bson.M{"$in": []string{"Medium", "High", "Extreme", "3", "4", "5"}}},
			}
		case "low":
			filter["$or"] = []bson.M{
				{"impactLevel": bson.M{"$in": []string{"Low", "Medium-Low", "1", "2"}}},
				{"likelihoodLevel": bson.M{"$in": []string{"Low", "Medium-Low", "1", "2"}}},
			}
		}
	}

	// Execute query (without pagination for now - simpler for drilldown)
	cursor, err := riskCollection.Find(ctx, filter, options.Find().
		SetLimit(50).
		SetSort(bson.D{{"riskScore", -1}}))
	
	if err != nil {
		log.Printf("Failed to fetch filtered risks: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch risks")
		return
	}
	defer cursor.Close(ctx)

	var risks []bson.M
	for cursor.Next(ctx) {
		var risk bson.M
		if err := cursor.Decode(&risk); err != nil {
			continue
		}
		// Convert ObjectID to string for JSON
		if id, ok := risk["_id"].(primitive.ObjectID); ok {
			risk["id"] = id.Hex()
		}
		risks = append(risks, risk)
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"risks": risks,
		"total": len(risks),
	})
}

// GetRisksByAsset returns risks associated with a specific asset
func GetRisksByAsset(w http.ResponseWriter, r *http.Request) {
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

	// Get asset ID from path parameter
	vars := mux.Vars(r)
	assetIDStr := vars["assetId"]
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

	filter := bson.M{
		"organizationId": orgID,
		"assetId":        assetID,
	}

	opts := options.Find().SetSort(bson.D{{"createdAt", -1}})

	cursor, err := riskCollection.Find(ctx, filter, opts)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithJSON(w, http.StatusOK, []models.Risk{})
			return
		}
		log.Printf("risks by asset Find error: %v", err)
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

// ResubmitAnalystRisk allows an analyst to resubmit a rejected or cancelled risk
func ResubmitAnalystRisk(w http.ResponseWriter, r *http.Request) {
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

	// First, find the risk to ensure it exists and belongs to this analyst
	var risk bson.M
	err = riskCollection.FindOne(ctx, bson.M{
		"_id":            riskID,
		"organizationId": orgID,
		"createdBy":      userIDStr,
	}).Decode(&risk)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			utils.RespondWithError(w, http.StatusNotFound, "risk not found")
		} else {
			utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch risk")
		}
		return
	}

	// Check if risk is in a state that can be resubmitted
	currentStatus, ok := risk["status"].(string)
	if !ok {
		currentStatus = ""
	}

	allowedStatuses := []string{"rejected", "cancelled", "draft"}
	canResubmit := false
	for _, s := range allowedStatuses {
		if s == currentStatus {
			canResubmit = true
			break
		}
	}

	if !canResubmit {
		utils.RespondWithError(w, http.StatusBadRequest, 
			"risk cannot be resubmitted. Current status: " + currentStatus)
		return
	}

	// Update the risk status back to pending
	update := bson.M{
		"$set": bson.M{
			"status":           "pending",
			"updatedAt":        time.Now().UTC(),
			"lastSubmittedAt":  time.Now().UTC(),
		},
		"$push": bson.M{
			"history": bson.M{
				"action": "resubmitted",
				"by":     userIDStr,
				"at":     time.Now().UTC(),
				"note":   "Risk resubmitted for approval",
			},
		},
	}

	result, err := riskCollection.UpdateOne(ctx, 
		bson.M{"_id": riskID, "organizationId": orgID, "createdBy": userIDStr},
		update,
	)

	if err != nil {
		log.Printf("ResubmitAnalystRisk - update error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to resubmit risk")
		return
	}

	if result.MatchedCount == 0 {
		utils.RespondWithError(w, http.StatusNotFound, "risk not found")
		return
	}

	// Also create a new approval record for this resubmission
	approvalTitle := "Risk Resubmission"
	if title, ok := risk["title"].(string); ok && title != "" {
		approvalTitle = "Risk Resubmission: " + title
	}

	approval := bson.M{
		"_id":               primitive.NewObjectID(),
		"organizationId":    orgID,
		"title":             approvalTitle,
		"riskId":            riskID,
		"riskTitle":         risk["title"],
		"type":              "risk_submission",
		"status":            "pending",
		"submittedBy":       userIDStr,
		"submittedAt":       time.Now().UTC(),
		"currentLevel":      1,
		"totalLevels":       1,
		"isResubmission":    true,
		"originalApprovalId": risk["lastApprovalId"],
		"createdAt":         time.Now().UTC(),
		"updatedAt":         time.Now().UTC(),
	}

	_, err = approvalCollection.InsertOne(ctx, approval)
	if err != nil {
		log.Printf("ResubmitAnalystRisk - create approval error: %v", err)
		// Continue anyway since the risk was updated
	}

	// Update the risk with the new approval ID
	_, _ = riskCollection.UpdateOne(ctx, 
		bson.M{"_id": riskID},
		bson.M{"$set": bson.M{"lastApprovalId": approval["_id"]}},
	)

	// Get updated risk
	var updatedRisk bson.M
	_ = riskCollection.FindOne(ctx, bson.M{"_id": riskID}).Decode(&updatedRisk)

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message":  "Risk resubmitted successfully",
		"risk":     updatedRisk,
		"approval": approval,
	})
}
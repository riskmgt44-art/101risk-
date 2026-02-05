package handlers

import (
	"context"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/utils"
)

type HeatmapResponse struct {
	Departments *DepartmentHeatmap `json:"departments,omitempty"`
	Locations   *LocationHeatmap   `json:"locations,omitempty"`
	Categories  []CategoryData     `json:"categories,omitempty"`
}

type DepartmentHeatmap struct {
	Departments []DeptData `json:"departments"`
	Stats       DeptStats  `json:"stats"`
}

type DeptData struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	RiskScore float64 `json:"riskScore"`
	RiskCount int64   `json:"riskCount"`
	Trend     float64 `json:"trend,omitempty"`
}

type DeptStats struct {
	TotalDepartments    int     `json:"totalDepartments"`
	AverageRiskScore    float64 `json:"averageRiskScore"`
	TotalRisks          int64   `json:"totalRisks"`
	HighRiskDepartments int     `json:"highRiskDepartments"`
}

type LocationHeatmap struct {
	Regions    []string    `json:"regions"`
	Categories []string    `json:"categories"`
	Matrix     [][]int64   `json:"matrix"`
	TotalRisks int64       `json:"totalRisks"`
}

type CategoryData struct {
	Type  string  `json:"type"`
	Value float64 `json:"value"`
	Count int64   `json:"count"`
}

func GetHeatmapData(w http.ResponseWriter, r *http.Request) {
	orgIDHex, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDHex == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "Organization ID not found")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDHex)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid organization ID")
		return
	}

	view := r.URL.Query().Get("view")
	if view == "" {
		view = "dept"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var response HeatmapResponse

	switch view {
	case "dept":
		deptData, err := getDepartmentHeatmap(ctx, orgID, r.URL.Query())
		if err != nil {
			log.Printf("Failed to fetch department data: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch department data")
			return
		}
		response.Departments = deptData

	case "location":
		locationData, err := getLocationHeatmap(ctx, orgID, r.URL.Query())
		if err != nil {
			log.Printf("Failed to fetch location data: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch location data")
			return
		}
		response.Locations = locationData

	case "category":
		categoryData, err := getCategoryHeatmap(ctx, orgID, r.URL.Query())
		if err != nil {
			log.Printf("Failed to fetch category data: %v", err)
			utils.RespondWithError(w, http.StatusInternalServerError, "Failed to fetch category data")
			return
		}
		response.Categories = categoryData

	default:
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid view type")
		return
	}

	utils.RespondWithJSON(w, http.StatusOK, map[string]interface{}{
		view: response,
	})
}

func getDepartmentHeatmap(ctx context.Context, orgID primitive.ObjectID, queryParams map[string][]string) (*DepartmentHeatmap, error) {
	// Build filter from query parameters
	filter := buildRiskFilter(orgID, queryParams)

	// Aggregate risks by department
	pipeline := mongo.Pipeline{
		bson.D{{"$match", filter}},
		bson.D{{"$group", bson.D{
			{"_id", "$department"},
			{"riskCount", bson.D{{"$sum", 1}}},
			{"avgRiskScore", bson.D{{"$avg", "$riskScore"}}},
		}}},
		bson.D{{"$sort", bson.D{{"riskCount", -1}}}},
	}

	cursor, err := riskCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var departments []DeptData
	var totalRiskScore float64
	var totalRisks int64

	for cursor.Next(ctx) {
		var result struct {
			ID           string  `bson:"_id"`
			RiskCount    int64   `bson:"riskCount"`
			AvgRiskScore float64 `bson:"avgRiskScore"`
		}

		if err := cursor.Decode(&result); err != nil {
			continue
		}

		if result.ID == "" {
			result.ID = "Unassigned"
		}

		departments = append(departments, DeptData{
			ID:        result.ID,
			Name:      result.ID,
			RiskScore: result.AvgRiskScore,
			RiskCount: result.RiskCount,
		})

		totalRiskScore += result.AvgRiskScore
		totalRisks += result.RiskCount
	}

	// Calculate stats
	avgRiskScore := 0.0
	if len(departments) > 0 {
		avgRiskScore = totalRiskScore / float64(len(departments))
	}

	// Calculate trend (simplified)
	for i := range departments {
		// Simple trend calculation
		if totalRisks > 0 {
			departments[i].Trend = (float64(departments[i].RiskCount) / float64(totalRisks)) * 100
		}
	}

	return &DepartmentHeatmap{
		Departments: departments,
		Stats: DeptStats{
			TotalDepartments:    len(departments),
			AverageRiskScore:    avgRiskScore,
			TotalRisks:          totalRisks,
			HighRiskDepartments: countHighRiskDepartments(departments),
		},
	}, nil
}

func getLocationHeatmap(ctx context.Context, orgID primitive.ObjectID, queryParams map[string][]string) (*LocationHeatmap, error) {
	filter := buildRiskFilter(orgID, queryParams)

	// Get unique regions
	regions, err := getUniqueValues(ctx, riskCollection, "region", filter)
	if err != nil {
		return nil, err
	}

	// Get unique categories
	categories, err := getUniqueValues(ctx, riskCollection, "category", filter)
	if err != nil {
		return nil, err
	}

	// Initialize matrix
	matrix := make([][]int64, len(categories))
	for i := range matrix {
		matrix[i] = make([]int64, len(regions))
	}

	// Get all risks and populate matrix
	cursor, err := riskCollection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	for cursor.Next(ctx) {
		var risk struct {
			Region   string `bson:"region"`
			Category string `bson:"category"`
		}
		if err := cursor.Decode(&risk); err != nil {
			continue
		}

		regionIndex := indexOf(regions, risk.Region)
		categoryIndex := indexOf(categories, risk.Category)

		if regionIndex >= 0 && categoryIndex >= 0 {
			matrix[categoryIndex][regionIndex]++
		}
	}

	// Calculate total risks
	var totalRisks int64
	for _, row := range matrix {
		for _, val := range row {
			totalRisks += val
		}
	}

	return &LocationHeatmap{
		Regions:    regions,
		Categories: categories,
		Matrix:     matrix,
		TotalRisks: totalRisks,
	}, nil
}

func getCategoryHeatmap(ctx context.Context, orgID primitive.ObjectID, queryParams map[string][]string) ([]CategoryData, error) {
	filter := buildRiskFilter(orgID, queryParams)

	pipeline := mongo.Pipeline{
		bson.D{{"$match", filter}},
		bson.D{{"$group", bson.D{
			{"_id", "$category"},
			{"count", bson.D{{"$sum", 1}}},
			{"avgRiskScore", bson.D{{"$avg", "$riskScore"}}},
		}}},
		bson.D{{"$sort", bson.D{{"count", -1}}}},
	}

	cursor, err := riskCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var categories []CategoryData
	for cursor.Next(ctx) {
		var result struct {
			ID           string  `bson:"_id"`
			Count        int64   `bson:"count"`
			AvgRiskScore float64 `bson:"avgRiskScore"`
		}

		if err := cursor.Decode(&result); err != nil {
			continue
		}

		if result.ID == "" {
			result.ID = "Uncategorized"
		}

		categories = append(categories, CategoryData{
			Type:  result.ID,
			Value: result.AvgRiskScore,
			Count: result.Count,
		})
	}

	return categories, nil
}

func buildRiskFilter(orgID primitive.ObjectID, queryParams map[string][]string) bson.M {
	filter := bson.M{
		"organizationId": orgID,
		"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	}

	// Apply time range filter
	if timeRange := getFirstParam(queryParams, "timeRange"); timeRange != "" {
		startDate := calculateStartDateForHeatmap(timeRange)
		if !startDate.IsZero() {
			filter["createdAt"] = bson.M{"$gte": startDate}
		}
	}

	// Apply severity filter
	if severity := getFirstParam(queryParams, "severity"); severity != "" {
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

	// Apply business unit filter
	if businessUnit := getFirstParam(queryParams, "businessUnit"); businessUnit != "" && businessUnit != "all" {
		filter["businessUnit"] = businessUnit
	}

	// Apply category filter
	if category := getFirstParam(queryParams, "riskCategory"); category != "" && category != "all" {
		filter["category"] = category
	}

	// Apply owner filter (simplified)
	if owner := getFirstParam(queryParams, "riskOwner"); owner != "" && owner != "all" {
		if owner == "unassigned" {
			filter["owner"] = bson.M{"$in": []interface{}{"", nil}}
		}
	}

	return filter
}

// CHANGED: Renamed function to avoid duplicate with risk_handler.go
func calculateStartDateForHeatmap(timeRange string) time.Time {
	now := time.Now()
	switch timeRange {
	case "30":
		return now.AddDate(0, 0, -30)
	case "90":
		return now.AddDate(0, 0, -90)
	case "180":
		return now.AddDate(0, 0, -180)
	case "ytd":
		return time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
	default:
		return time.Time{}
	}
}

func getUniqueValues(ctx context.Context, collection *mongo.Collection, field string, filter bson.M) ([]string, error) {
	pipeline := mongo.Pipeline{
		bson.D{{"$match", filter}},
		bson.D{{"$group", bson.D{{"_id", "$" + field}}}},
		bson.D{{"$sort", bson.D{{"_id", 1}}}},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return []string{}, err
	}
	defer cursor.Close(ctx)

	var values []string
	for cursor.Next(ctx) {
		var result struct {
			ID string `bson:"_id"`
		}
		if err := cursor.Decode(&result); err != nil {
			continue
		}
		if result.ID == "" {
			result.ID = "Unspecified"
		}
		values = append(values, result.ID)
	}

	if len(values) == 0 {
		values = []string{"General"}
	}

	return values, nil
}

func getFirstParam(params map[string][]string, key string) string {
	if values, ok := params[key]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func indexOf(slice []string, item string) int {
	for i, v := range slice {
		if v == item {
			return i
		}
	}
	return -1
}

func countHighRiskDepartments(departments []DeptData) int {
	count := 0
	for _, dept := range departments {
		if dept.RiskScore >= 40 {
			count++
		}
	}
	return count
}
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"riskmgt/utils"
)

type DashboardOverview struct {
	// KPIs
	TotalRisks          int64  `json:"totalRisks"`
	HighSeverityRisks   int64  `json:"highSeverityRisks"`
	PendingApprovals    int64  `json:"pendingApprovals"`
	ExposureIndex       string `json:"exposureIndex"`
	ActionsEffectiveness string `json:"actionsEffectiveness"`
	UpcomingReviews     int64  `json:"upcomingReviews"`
	
	// New asset-user metrics
	TotalAssets        int64 `json:"totalAssets"`
	AssetsWithUsers    int64 `json:"assetsWithUsers"`
	UsersWithAssets    int64 `json:"usersWithAssets"`
	
	// Trend percentages
	TotalRisksTrend    string `json:"totalRisksTrend"`
	HighRisksTrend     string `json:"highRisksTrend"`
	
	// Chart Data
	HeatMapData       []HeatMapPoint       `json:"heatMapData"`
	TrendData         TrendChartData       `json:"trendData"`
	ActionStatusData  ActionStatusData     `json:"actionStatusData"`
	RiskDriversData   RiskDriversData      `json:"riskDriversData"`
	RAMMovementData   RAMMovementData      `json:"ramMovementData"`
	AreaBarData       AreaBarData          `json:"areaBarData"`
	
	// Attention Items
	AttentionItems    []AttentionItem      `json:"attentionItems"`
}

type HeatMapPoint struct {
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
	R         float64 `json:"r"`
	Label     string  `json:"label"`
}

type TrendChartData struct {
	Labels   []string          `json:"labels"`
	Datasets []TrendDataset    `json:"datasets"`
}

type TrendDataset struct {
	Label           string    `json:"label"`
	Data            []float64 `json:"data"`
	BorderColor     string    `json:"borderColor"`
	BackgroundColor string    `json:"backgroundColor"`
	Fill            bool      `json:"fill"`
}

type ActionStatusData struct {
	Labels  []string `json:"labels"`
	Values  []int64  `json:"values"`
	Colors  []string `json:"colors"`
}

type RiskDriversData struct {
	Labels  []string `json:"labels"`
	Values  []int64  `json:"values"`
	Colors  []string `json:"colors"`
}

type RAMMovementData struct {
	Increased int64 `json:"increased"`
	Decreased int64 `json:"decreased"`
	Stable    int64 `json:"stable"`
}

type AreaBarData struct {
	Labels  []string `json:"labels"`
	Values  []int64  `json:"values"`
	Colors  []string `json:"colors"`
}

type AttentionItem struct {
	Title  string `json:"title"`
	Action string `json:"action"`
	Link   string `json:"link"`
}

func GetExecutiveOverview(w http.ResponseWriter, r *http.Request) {
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

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	var dashboard DashboardOverview
	
	// Use goroutines to fetch data in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Define error collector
	var fetchErrors []error
	
	// Function to safely update dashboard
	updateDashboard := func(updater func()) {
		mu.Lock()
		defer mu.Unlock()
		updater()
	}
	
	// Function to handle errors
	handleError := func(err error, operation string) {
		if err != nil && err != mongo.ErrNoDocuments {
			mu.Lock()
			fetchErrors = append(fetchErrors, fmt.Errorf("%s: %v", operation, err))
			mu.Unlock()
		}
	}
	
	// 1. Fetch basic counts in parallel - changed from 7 to 10
	wg.Add(10)
	
	// Total Active Risks
	go func() {
		defer wg.Done()
		count, err := riskCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
		})
		handleError(err, "TotalRisks")
		updateDashboard(func() { dashboard.TotalRisks = count })
	}()
	
	// High Severity Risks
	go func() {
		defer wg.Done()
		count, err := riskCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
			"$or": []bson.M{
				{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
				{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
			},
		})
		handleError(err, "HighSeverityRisks")
		updateDashboard(func() { dashboard.HighSeverityRisks = count })
	}()
	
	// Pending Approvals
	go func() {
		defer wg.Done()
		count, err := approvalCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         "pending",
		})
		handleError(err, "PendingApprovals")
		updateDashboard(func() { dashboard.PendingApprovals = count })
	}()
	
	// Upcoming Reviews
	go func() {
		defer wg.Done()
		next30d := time.Now().UTC().Add(30 * 24 * time.Hour)
		count, err := riskCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
			"nextReviewDate": bson.M{
				"$gte": time.Now().UTC(),
				"$lte": next30d,
			},
		})
		handleError(err, "UpcomingReviews")
		updateDashboard(func() { dashboard.UpcomingReviews = count })
	}()
	
	// Total Assets
	go func() {
		defer wg.Done()
		count, err := assetCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         "active",
		})
		handleError(err, "TotalAssets")
		updateDashboard(func() { dashboard.TotalAssets = count })
	}()
	
	// Assets with assigned users
	go func() {
		defer wg.Done()
		count, err := assetCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         "active",
			"assignedUserIds": bson.M{"$exists": true, "$ne": []primitive.ObjectID{}},
		})
		handleError(err, "AssetsWithUsers")
		updateDashboard(func() { dashboard.AssetsWithUsers = count })
	}()
	
	// Users with assets assigned
	go func() {
		defer wg.Done()
		count, err := userCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"deletedAt":      nil,
			"assetIds":       bson.M{"$exists": true, "$ne": []primitive.ObjectID{}},
		})
		handleError(err, "UsersWithAssets")
		updateDashboard(func() { dashboard.UsersWithAssets = count })
	}()
	
	// Actions effectiveness data
	var completedActions, totalActions int64
	go func() {
		defer wg.Done()
		completed, err1 := actionCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status": "completed",
		})
		total, err2 := actionCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status": bson.M{"$in": []string{"open", "in-progress", "completed", "on-hold"}},
		})
		
		handleError(err1, "CompletedActions")
		handleError(err2, "TotalActions")
		completedActions = completed
		totalActions = total
	}()
	
	// Previous period data for trends
	var previousTotalRisks, previousHighRisks int64
	go func() {
		defer wg.Done()
		thirtyDaysAgo := time.Now().UTC().Add(-30 * 24 * time.Hour)
		
		prevTotal, err1 := riskCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
			"createdAt":      bson.M{"$lt": thirtyDaysAgo},
		})
		
		prevHigh, err2 := riskCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
			"createdAt":      bson.M{"$lt": thirtyDaysAgo},
			"$or": []bson.M{
				{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
				{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
			},
		})
		
		handleError(err1, "PreviousTotalRisks")
		handleError(err2, "PreviousHighRisks")
		previousTotalRisks = prevTotal
		previousHighRisks = prevHigh
	}()
	
	// Average risk score for exposure index
	var avgRiskScore float64
	go func() {
		defer wg.Done()
		pipeline := mongo.Pipeline{
			bson.D{{"$match", bson.M{
				"organizationId": orgID,
				"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
			}}},
			bson.D{{"$group", bson.M{
				"_id": nil,
				"avgRiskScore": bson.M{"$avg": "$riskScore"},
			}}},
		}
		
		cursor, err := riskCollection.Aggregate(ctx, pipeline)
		if err == nil && cursor.Next(ctx) {
			var result struct {
				AvgRiskScore float64 `bson:"avgRiskScore"`
			}
			cursor.Decode(&result)
			avgRiskScore = result.AvgRiskScore
		}
		if cursor != nil {
			cursor.Close(ctx)
		}
	}()
	
	// Wait for all goroutines to complete
	wg.Wait()
	
	// Calculate derived values
	dashboard.TotalRisksTrend = calculateTrend(dashboard.TotalRisks, previousTotalRisks)
	dashboard.HighRisksTrend = calculateTrend(dashboard.HighSeverityRisks, previousHighRisks)
	dashboard.ExposureIndex = calculateExposureIndexFromScore(avgRiskScore, dashboard.TotalRisks, dashboard.HighSeverityRisks)
	dashboard.ActionsEffectiveness = calculateEffectivenessFromCounts(completedActions, totalActions)
	
	// Now fetch chart data (these can be heavy, so do them one at a time or in smaller batches)
	// But first, check if we have any data to avoid unnecessary queries
	if dashboard.TotalRisks > 0 {
		wg.Add(6)
		
		go func() {
			defer wg.Done()
			updateDashboard(func() { dashboard.HeatMapData = getHeatMapData(ctx, orgID) })
		}()
		
		go func() {
			defer wg.Done()
			updateDashboard(func() { dashboard.TrendData = getTrendData(ctx, orgID) })
		}()
		
		go func() {
			defer wg.Done()
			updateDashboard(func() { dashboard.ActionStatusData = getActionStatusData(ctx, orgID) })
		}()
		
		go func() {
			defer wg.Done()
			updateDashboard(func() { dashboard.RiskDriversData = getRiskDriversData(ctx, orgID) })
		}()
		
		go func() {
			defer wg.Done()
			updateDashboard(func() { dashboard.RAMMovementData = getRAMMovementData(ctx, orgID) })
		}()
		
		go func() {
			defer wg.Done()
			updateDashboard(func() { dashboard.AreaBarData = getAreaBarData(ctx, orgID) })
		}()
		
		wg.Wait()
	}
	
	// Get attention items
	dashboard.AttentionItems = getAttentionItems(ctx, orgID)
	
	// Log any errors
	if len(fetchErrors) > 0 {
		for _, err := range fetchErrors {
			log.Printf("Dashboard fetch error: %v", err)
		}
	}
	
	utils.RespondWithJSON(w, http.StatusOK, dashboard)
}

// Helper function to calculate trend percentage
func calculateTrend(current, previous int64) string {
	if previous == 0 {
		if current == 0 {
			return "0%"
		}
		return "+100%"
	}
	
	change := float64(current-previous) / float64(previous) * 100
	if change >= 0 {
		return fmt.Sprintf("+%.0f%%", change)
	}
	return fmt.Sprintf("%.0f%%", change)
}

// Simplified helper functions
func calculateExposureIndexFromScore(avgScore float64, totalRisks, highRisks int64) string {
	if totalRisks == 0 {
		return "Low"
	}
	
	if avgScore > 70 {
		return "High"
	} else if avgScore > 40 {
		return "Medium"
	}
	
	// Fallback
	highRiskPercentage := float64(highRisks) / float64(totalRisks) * 100
	if highRiskPercentage > 30 {
		return "High"
	} else if highRiskPercentage > 15 {
		return "Medium"
	}
	return "Low"
}

func calculateEffectivenessFromCounts(completed, total int64) string {
	if total == 0 {
		return "100%"
	}
	effectiveness := float64(completed) / float64(total) * 100
	return fmt.Sprintf("%.0f%%", effectiveness)
}

// Optimized chart data functions - with simpler queries

func getHeatMapData(ctx context.Context, orgID primitive.ObjectID) []HeatMapPoint {
	// If you have few risks, use a simpler approach
	// First check count
	count, _ := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	})
	
	if count == 0 {
		return []HeatMapPoint{}
	}
	
	// For small datasets, fetch all and process in memory
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
		"likelihoodLevel": bson.M{"$exists": true},
		"impactLevel": bson.M{"$exists": true},
	})
	
	if err != nil {
		return []HeatMapPoint{}
	}
	defer cursor.Close(ctx)
	
	// Group in memory
	groups := make(map[string]int)
	
	for cursor.Next(ctx) {
		var risk struct {
			LikelihoodLevel string `bson:"likelihoodLevel"`
			ImpactLevel     string `bson:"impactLevel"`
		}
		if err := cursor.Decode(&risk); err == nil {
			key := risk.LikelihoodLevel + "|" + risk.ImpactLevel
			groups[key]++
		}
	}
	
	// Convert to heat map points
	likelihoodMap := map[string]float64{
		"Rare": 1, "1": 1, "Low": 1,
		"Unlikely": 2, "2": 2, "Medium-Low": 2,
		"Possible": 3, "3": 3, "Medium": 3,
		"Likely": 4, "4": 4, "Medium-High": 4,
		"Almost Certain": 5, "5": 5, "High": 5,
	}
	
	impactMap := map[string]float64{
		"Insignificant": 1, "1": 1, "Low": 1,
		"Minor": 2, "2": 2, "Medium-Low": 2,
		"Moderate": 3, "3": 3, "Medium": 3,
		"Major": 4, "4": 4, "Medium-High": 4,
		"Catastrophic": 5, "5": 5, "High": 5,
	}
	
	var points []HeatMapPoint
	for key, count := range groups {
		// Parse key (format: "likelihood|impact")
		var likelihood, impact string
		for i, char := range key {
			if char == '|' {
				likelihood = key[:i]
				impact = key[i+1:]
				break
			}
		}
		
		x := likelihoodMap[likelihood]
		y := impactMap[impact]
		
		if x > 0 && y > 0 {
			r := float64(count) * 2
			if r < 5 {
				r = 5
			}
			if r > 20 {
				r = 20
			}
			
			points = append(points, HeatMapPoint{
				X:     x,
				Y:     y,
				R:     r,
				Label: fmt.Sprintf("%d risks", count),
			})
		}
	}
	
	return points
}

func getTrendData(ctx context.Context, orgID primitive.ObjectID) TrendChartData {
	var trendData TrendChartData
	
	// Simplified: just get current counts for demo
	// In production, you'd want to cache this or pre-aggregate
	now := time.Now()
	months := []string{}
	
	// Just show last 3 months to reduce queries
	for i := 2; i >= 0; i-- {
		month := now.AddDate(0, -i, 0)
		months = append(months, month.Format("Jan"))
	}
	
	trendData.Labels = months
	
	// Use current counts for all months (simplified for demo)
	// In real app, you'd query each month
	totalCount, _ := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	})
	
	highCount, _ := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
		"$or": []bson.M{
			{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
			{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
		},
	})
	
	// Create simple trend data
	totalData := []float64{float64(totalCount) * 0.8, float64(totalCount) * 0.9, float64(totalCount)}
	highData := []float64{float64(highCount) * 0.7, float64(highCount) * 0.85, float64(highCount)}
	
	trendData.Datasets = []TrendDataset{
		{
			Label:           "Total Risks",
			Data:            totalData,
			BorderColor:     "#ef4444",
			BackgroundColor: "rgba(239,68,68,0.1)",
			Fill:            true,
		},
		{
			Label:           "High Risks",
			Data:            highData,
			BorderColor:     "#f59e0b",
			BackgroundColor: "rgba(245,158,11,0.1)",
			Fill:            true,
		},
	}
	
	return trendData
}

func getActionStatusData(ctx context.Context, orgID primitive.ObjectID) ActionStatusData {
	var data ActionStatusData
	
	// For small datasets, fetch once and categorize
	cursor, err := actionCollection.Find(ctx, bson.M{
		"organizationId": orgID,
	})
	
	if err != nil {
		return data
	}
	defer cursor.Close(ctx)
	
	// Count in memory
	counts := map[string]int64{
		"not-started": 0,
		"in-progress": 0,
		"on-hold":     0,
		"completed":   0,
		"cancelled":   0,
	}
	
	for cursor.Next(ctx) {
		var action struct {
			Status string `bson:"status"`
		}
		if err := cursor.Decode(&action); err == nil {
			if count, exists := counts[action.Status]; exists {
				counts[action.Status] = count + 1
			} else {
				counts["not-started"]++
			}
		}
	}
	
	// Build response
	statusOrder := []string{"not-started", "in-progress", "on-hold", "completed", "cancelled"}
	labels := []string{"Not Started", "In Progress", "On Hold", "Completed", "Cancelled"}
	colors := []string{"#f59e0b", "#5DA1A1", "#3b82f6", "#10b981", "#6b7280"}
	
	for i, status := range statusOrder {
		if counts[status] > 0 {
			data.Labels = append(data.Labels, labels[i])
			data.Values = append(data.Values, counts[status])
			data.Colors = append(data.Colors, colors[i])
		}
	}
	
	return data
}

func getRiskDriversData(ctx context.Context, orgID primitive.ObjectID) RiskDriversData {
	var data RiskDriversData
	
	// For small datasets, fetch and process in memory
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	})
	
	if err != nil {
		return data
	}
	defer cursor.Close(ctx)
	
	// Count categories in memory
	categoryCounts := make(map[string]int64)
	
	for cursor.Next(ctx) {
		var risk struct {
			Category string `bson:"category"`
		}
		if err := cursor.Decode(&risk); err == nil && risk.Category != "" {
			categoryCounts[risk.Category]++
		}
	}
	
	// Get top 5 categories
	colors := []string{"#ef4444", "#f59e0b", "#5DA1A1", "#9ca3af", "#3b82f6"}
	colorIndex := 0
	
	for category, count := range categoryCounts {
		if colorIndex >= 5 {
			break
		}
		data.Labels = append(data.Labels, category)
		data.Values = append(data.Values, count)
		data.Colors = append(data.Colors, colors[colorIndex])
		colorIndex++
	}
	
	// If no categories found, add a default
	if len(data.Labels) == 0 {
		data.Labels = []string{"Uncategorized"}
		data.Values = []int64{1}
		data.Colors = []string{"#9ca3af"}
	}
	
	return data
}

func getRAMMovementData(ctx context.Context, orgID primitive.ObjectID) RAMMovementData {
	var data RAMMovementData
	
	// Check risks that have been updated in last 90 days
	ninetyDaysAgo := time.Now().UTC().Add(-90 * 24 * time.Hour)
	
	// Get all risks and analyze in memory
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
		"updatedAt": bson.M{"$gte": ninetyDaysAgo},
	})
	
	if err != nil {
		// Return default values if error
		return RAMMovementData{Increased: 0, Decreased: 0, Stable: 0}
	}
	defer cursor.Close(ctx)
	
	for cursor.Next(ctx) {
		var risk struct {
			RiskScore float64 `bson:"riskScore"`
		}
		if err := cursor.Decode(&risk); err == nil {
			if risk.RiskScore > 50 {
				data.Increased++
			} else if risk.RiskScore < 30 {
				data.Decreased++
			} else {
				data.Stable++
			}
		}
	}
	
	return data
}

func getAreaBarData(ctx context.Context, orgID primitive.ObjectID) AreaBarData {
	var data AreaBarData
	
	// For small datasets, fetch and process in memory
	cursor, err := riskCollection.Find(ctx, bson.M{
		"organizationId": orgID,
		"status": bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
	})
	
	if err != nil {
		return data
	}
	defer cursor.Close(ctx)
	
	// Count departments in memory
	departmentCounts := make(map[string]int64)
	
	for cursor.Next(ctx) {
		var risk struct {
			Department string `bson:"department"`
		}
		if err := cursor.Decode(&risk); err == nil && risk.Department != "" {
			departmentCounts[risk.Department]++
		}
	}
	
	// Add to response with colors
	colors := []string{"#5DA1A1", "#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#9ca3af", "#8b5cf6"}
	colorIndex := 0
	
	for department, count := range departmentCounts {
		data.Labels = append(data.Labels, department)
		data.Values = append(data.Values, count)
		
		if colorIndex < len(colors) {
			data.Colors = append(data.Colors, colors[colorIndex])
			colorIndex++
		} else {
			data.Colors = append(data.Colors, "#5DA1A1") // Default color
		}
	}
	
	// If no departments found, use default
	if len(data.Labels) == 0 {
		data.Labels = []string{"General"}
		data.Values = []int64{1}
		data.Colors = []string{"#5DA1A1"}
	}
	
	return data
}

func getAttentionItems(ctx context.Context, orgID primitive.ObjectID) []AttentionItem {
	var items []AttentionItem
	
	// 1. OVERDUE ACTIONS
	overdueCount, err := actionCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status":         bson.M{"$in": []string{"open", "in-progress"}},
		"dueDate":        bson.M{"$exists": true, "$lt": time.Now().UTC()},
	})
	
	if err == nil && overdueCount > 0 {
		items = append(items, AttentionItem{
			Title:  fmt.Sprintf("%d Overdue Actions", overdueCount),
			Action: "Review",
			Link:   "/actions?filter=overdue",
		})
	}
	
	// 2. HIGH RISKS WITHOUT ACTION PLANS (simplified check)
	highRiskCount, err := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
		"$or": []bson.M{
			{"impactLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
			{"likelihoodLevel": bson.M{"$in": []string{"High", "Extreme", "4", "5", "Critical"}}},
		},
	})
	
	if err == nil && highRiskCount > 0 {
		// Check if any high risks have no action plan (simplified)
		items = append(items, AttentionItem{
			Title:  fmt.Sprintf("%d High Severity Risks", highRiskCount),
			Action: "Review",
			Link:   "/risks?filter=high",
		})
	}
	
	// 3. PENDING APPROVALS (older than 24 hours)
	pendingCount, err := approvalCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status":         "pending",
		"createdAt":      bson.M{"$lt": time.Now().UTC().Add(-24 * time.Hour)},
	})
	
	if err == nil && pendingCount > 0 {
		items = append(items, AttentionItem{
			Title:  fmt.Sprintf("%d Pending Approvals", pendingCount),
			Action: "Review",
			Link:   "/approvals",
		})
	}
	
	// 4. UPCOMING REVIEWS (within 7 days)
	next7d := time.Now().UTC().Add(7 * 24 * time.Hour)
	upcomingReviews, err := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status":         bson.M{"$nin": []string{"closed", "mitigated", "archived"}},
		"nextReviewDate": bson.M{
			"$gte": time.Now().UTC(),
			"$lte": next7d,
		},
	})
	
	if err == nil && upcomingReviews > 0 {
		items = append(items, AttentionItem{
			Title:  fmt.Sprintf("%d Risks Due for Review", upcomingReviews),
			Action: "Schedule",
			Link:   "/risks?filter=upcoming-review",
		})
	}
	
	// 5. ASSETS WITHOUT ASSIGNED USERS
	assetsWithoutUsers, err := assetCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status":         "active",
		"$or": []bson.M{
			{"assignedUserIds": bson.M{"$exists": false}},
			{"assignedUserIds": []primitive.ObjectID{}},
		},
	})
	
	if err == nil && assetsWithoutUsers > 0 {
		items = append(items, AttentionItem{
			Title:  fmt.Sprintf("%d Assets Without Assigned Users", assetsWithoutUsers),
			Action: "Assign",
			Link:   "/assets?filter=unassigned",
		})
	}
	
	// 6. EXPIRED MITIGATIONS (if you have this field)
	expiredMitigations, _ := riskCollection.CountDocuments(ctx, bson.M{
		"organizationId": orgID,
		"status":         "mitigated",
		"mitigationExpiry": bson.M{
			"$lt": time.Now().UTC(),
		},
	})
	
	if expiredMitigations > 0 {
		items = append(items, AttentionItem{
			Title:  fmt.Sprintf("%d Expired Mitigations", expiredMitigations),
			Action: "Review",
			Link:   "/risks?filter=expired-mitigation",
		})
	}
	
	return items
}
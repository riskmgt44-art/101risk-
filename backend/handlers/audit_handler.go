package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"riskmgt/models"
	"riskmgt/utils"
)

// REMOVED DUPLICATE COLLECTION DECLARATIONS - They're already in collections.go

// Initialize function - call this in your main setup
func InitAuditHandlers() {
	// Start the hub
	go hub.Run()
}

// Everything below remains EXACTLY AS YOU HAD IT
// Only removing the duplicate helper functions at the end

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type BroadcastMessage struct {
	OrgID   string
	Message []byte
}

type Hub struct {
	clients    map[string]map[*Client]bool
	broadcast  chan BroadcastMessage
	register   chan *Client
	unregister chan *Client
	mutex      sync.Mutex
}

type Client struct {
	orgID    string
	userID   string
	userRole string
	conn     *websocket.Conn
	send     chan []byte
	hub      *Hub
}

var hub = &Hub{
	clients:    make(map[string]map[*Client]bool),
	broadcast:  make(chan BroadcastMessage),
	register:   make(chan *Client),
	unregister: make(chan *Client),
}

func GetHub() *Hub {
	return hub
}

func (h *Hub) Run() {
	log.Println("WebSocket hub started")
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			if _, ok := h.clients[client.orgID]; !ok {
				h.clients[client.orgID] = make(map[*Client]bool)
			}
			h.clients[client.orgID][client] = true
			h.mutex.Unlock()

		case client := <-h.unregister:
			h.mutex.Lock()
			if clients, ok := h.clients[client.orgID]; ok {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					close(client.send)
					if len(clients) == 0 {
						delete(h.clients, client.orgID)
					}
				}
			}
			h.mutex.Unlock()

		case bm := <-h.broadcast:
			h.mutex.Lock()
			if clients, ok := h.clients[bm.OrgID]; ok {
				for client := range clients {
					select {
					case client.send <- bm.Message:
					default:
						close(client.send)
						delete(clients, client)
					}
				}
			}
			h.mutex.Unlock()
		}
	}
}

// BroadcastAudit sends a new audit log to all clients in the same organization
func BroadcastAudit(audit *models.AuditLog) {
	// Convert to map with proper JSON serialization
	auditMap := map[string]interface{}{
		"_id":             audit.ID,
		"organizationId":  audit.OrganizationID,
		"userId":          audit.UserID,
		"userEmail":       audit.UserEmail,
		"userRole":        audit.UserRole,
		"entityType":      audit.EntityType,
		"entityId":        audit.EntityID,
		"action":          audit.Action,
		"details":         audit.Details,
		"createdAt":       audit.CreatedAt,
		"ipAddress":       audit.IPAddress,
		"userAgent":       audit.UserAgent,
	}
	
	data, err := json.Marshal(auditMap)
	if err != nil {
		log.Printf("Failed to marshal audit for WS: %v", err)
		return
	}
	hub.broadcast <- BroadcastMessage{OrgID: audit.OrganizationID.Hex(), Message: data}
}

// WS handler
func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	tokenString := r.URL.Query().Get("token")
	
	if tokenString == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}
	
	if tokenString == "" {
		http.Error(w, "Authentication token required", http.StatusUnauthorized)
		return
	}
	
	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}
	
	orgIDStr := claims.OrganizationID
	userIDStr := claims.UserID
	userRole := claims.Role
	
	if orgIDStr == "" || userIDStr == "" {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}
	
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "WebSocket upgrade failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	client := &Client{
		orgID:    orgIDStr,
		userID:   userIDStr,
		userRole: userRole,
		conn:     conn,
		send:     make(chan []byte, 256),
		hub:      hub,
	}
	
	client.hub.register <- client
	
	// Write pump
	go func() {
		defer func() {
			client.hub.unregister <- client
			conn.Close()
		}()
		for {
			select {
			case message, ok := <-client.send:
				if !ok {
					conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
					return
				}
				
				if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
					return
				}
			}
		}
	}()
	
	// Read pump
	go func() {
		defer func() {
			client.hub.unregister <- client
			conn.Close()
		}()
		
		conn.SetReadLimit(512)
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})
		
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		go func() {
			for range ticker.C {
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}()
		
		for {
			messageType, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
			
			if messageType == websocket.PingMessage {
				conn.WriteMessage(websocket.PongMessage, nil)
			} else if messageType == websocket.CloseMessage {
				break
			}
		}
	}()
	
	// Send welcome message
	welcome := map[string]interface{}{
		"type":      "welcome",
		"message":   "Connected to audit log stream",
		"orgID":     orgIDStr,
		"userID":    userIDStr,
		"role":      userRole,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	welcomeBytes, _ := json.Marshal(welcome)
	conn.WriteMessage(websocket.TextMessage, welcomeBytes)
}

// ListAuditLogs returns paginated audit logs for the organization
func ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	userRole, _ := r.Context().Value("userRole").(string)
	
	if userRole == "analyst" {
		ListAnalystAuditLogs(w, r)
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			limit = 50
		}
	}

	skipStr := r.URL.Query().Get("skip")
	skip := 0
	if skipStr != "" {
		skip, err = strconv.Atoi(skipStr)
		if err != nil || skip < 0 {
			skip = 0
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	filter := bson.M{"organizationId": orgID}
	
	// Apply filters from query
	if entityType := r.URL.Query().Get("entityType"); entityType != "" && entityType != "all" {
		filter["entityType"] = entityType
	}
	
	if action := r.URL.Query().Get("action"); action != "" && action != "all" {
		filter["action"] = bson.M{"$regex": action, "$options": "i"}
	}
	
	if userID := r.URL.Query().Get("userId"); userID != "" && userID != "all" {
		userObjID, err := primitive.ObjectIDFromHex(userID)
		if err == nil {
			filter["userID"] = userObjID
		}
	}
	
	if timeRange := r.URL.Query().Get("timeRange"); timeRange != "" {
		startDate := calculateStartDate(timeRange)
		if !startDate.IsZero() {
			filter["createdAt"] = bson.M{"$gte": startDate}
		}
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "createdAt", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cursor, err := auditLogCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("audit find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch audit logs")
		return
	}
	defer cursor.Close(ctx)

	var logs []models.AuditLog
	if err = cursor.All(ctx, &logs); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode audit logs")
		return
	}

	if logs == nil {
		logs = []models.AuditLog{}
	}

	// Convert logs to proper JSON format
	jsonLogs := convertAuditLogsToJSON(logs)

	utils.RespondWithJSON(w, http.StatusOK, jsonLogs)
}

// ListAnalystAuditLogs returns audit logs filtered for analyst's assigned assets
func ListAnalystAuditLogs(w http.ResponseWriter, r *http.Request) {
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

	userRole, _ := r.Context().Value("userRole").(string)
	
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, userRole)
	
	filter := bson.M{
		"organizationId": orgID,
		"$or": []bson.M{
			{"userID": userID},
		},
	}

	if len(assignedAssetIDs) > 0 {
		riskIDs := getAnalystRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
		actionIDs := getAnalystActionIDsForRisks(ctx, orgID, riskIDs)
		
		orConditions := filter["$or"].([]bson.M)
		
		orConditions = append(orConditions, bson.M{
			"$and": []bson.M{
				{"entityType": "asset"},
				{"entityID": bson.M{"$in": assignedAssetIDs}},
			},
		})
		
		if len(riskIDs) > 0 {
			orConditions = append(orConditions, bson.M{
				"$and": []bson.M{
					{"entityType": "risk"},
					{"entityID": bson.M{"$in": riskIDs}},
				},
			})
		}
		
		if len(actionIDs) > 0 {
			orConditions = append(orConditions, bson.M{
				"$and": []bson.M{
					{"entityType": "action"},
					{"entityID": bson.M{"$in": actionIDs}},
				},
			})
		}
		
		filter["$or"] = orConditions
	}
	
	if entityType := r.URL.Query().Get("entityType"); entityType != "" && entityType != "all" {
		orConditions := filter["$or"].([]bson.M)
		newOrConditions := []bson.M{}
		for _, condition := range orConditions {
			if condition["$and"] != nil {
				andConditions := condition["$and"].([]bson.M)
				andConditions = append(andConditions, bson.M{"entityType": entityType})
				newOrConditions = append(newOrConditions, bson.M{
					"$and": andConditions,
				})
			} else if len(condition) == 1 && condition["userID"] != nil {
				newCondition := bson.M{
					"userID":     condition["userID"],
					"entityType": entityType,
				}
				newOrConditions = append(newOrConditions, newCondition)
			} else {
				newOrConditions = append(newOrConditions, condition)
			}
		}
		filter["$or"] = newOrConditions
	}
	
	if action := r.URL.Query().Get("action"); action != "" && action != "all" {
		filter["action"] = bson.M{"$regex": action, "$options": "i"}
	}
	
	if timeRange := r.URL.Query().Get("timeRange"); timeRange != "" {
		startDate := calculateStartDate(timeRange)
		if !startDate.IsZero() {
			filter["createdAt"] = bson.M{"$gte": startDate}
		}
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		limit, err = strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			limit = 50
		}
	}

	skipStr := r.URL.Query().Get("skip")
	skip := 0
	if skipStr != "" {
		skip, err = strconv.Atoi(skipStr)
		if err != nil || skip < 0 {
			skip = 0
		}
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "createdAt", Value: -1}}).
		SetLimit(int64(limit)).
		SetSkip(int64(skip))

	cursor, err := auditLogCollection.Find(ctx, filter, opts)
	if err != nil {
		log.Printf("analyst audit find error: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to fetch audit logs")
		return
	}
	defer cursor.Close(ctx)

	var logs []models.AuditLog
	if err = cursor.All(ctx, &logs); err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "failed to decode audit logs")
		return
	}

	if logs == nil {
		logs = []models.AuditLog{}
	}

	jsonLogs := convertAuditLogsToJSON(logs)
	utils.RespondWithJSON(w, http.StatusOK, jsonLogs)
}

// GetAnalystAuditStats returns statistics for analyst's audit view
func GetAnalystAuditStats(w http.ResponseWriter, r *http.Request) {
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

	userRole, _ := r.Context().Value("userRole").(string)
	
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, userRole)
	
	stats := map[string]interface{}{
		"totalEvents":      0,
		"myEvents":         0,
		"assetEvents":      0,
		"riskEvents":       0,
		"actionEvents":     0,
		"highRiskEvents":   0,
		"last24Hours":      0,
		"last7Days":        0,
		"deletesRestores":  0,
		"approvalEvents":   0,
	}

	baseFilter := bson.M{
		"organizationId": orgID,
		"$or": []bson.M{
			{"userID": userID},
		},
	}

	if len(assignedAssetIDs) > 0 {
		riskIDs := getAnalystRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
		actionIDs := getAnalystActionIDsForRisks(ctx, orgID, riskIDs)
		
		orConditions := baseFilter["$or"].([]bson.M)
		
		orConditions = append(orConditions, bson.M{
			"$and": []bson.M{
				{"entityType": "asset"},
				{"entityID": bson.M{"$in": assignedAssetIDs}},
			},
		})
		
		if len(riskIDs) > 0 {
			orConditions = append(orConditions, bson.M{
				"$and": []bson.M{
					{"entityType": "risk"},
					{"entityID": bson.M{"$in": riskIDs}},
				},
			})
		}
		
		if len(actionIDs) > 0 {
			orConditions = append(orConditions, bson.M{
				"$and": []bson.M{
					{"entityType": "action"},
					{"entityID": bson.M{"$in": actionIDs}},
				},
			})
		}
		
		baseFilter["$or"] = orConditions
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	updateStat := func(key string, value interface{}) {
		mu.Lock()
		stats[key] = value
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		count, _ := auditLogCollection.CountDocuments(ctx, baseFilter)
		updateStat("totalEvents", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		count, _ := auditLogCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"userID": userID,
		})
		updateStat("myEvents", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
		count, _ := auditLogCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"createdAt": bson.M{"$gte": twentyFourHoursAgo},
			"userID": userID,
		})
		updateStat("last24Hours", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
		sevenDayFilter := bson.M{}
		for k, v := range baseFilter {
			sevenDayFilter[k] = v
		}
		sevenDayFilter["createdAt"] = bson.M{"$gte": sevenDaysAgo}
		count, _ := auditLogCollection.CountDocuments(ctx, sevenDayFilter)
		updateStat("last7Days", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		highRiskFilter := bson.M{}
		for k, v := range baseFilter {
			highRiskFilter[k] = v
		}
		highRiskFilter["action"] = bson.M{"$in": []string{
			"delete", "restore", "override", "security_breach", "unauthorized_access",
		}}
		count, _ := auditLogCollection.CountDocuments(ctx, highRiskFilter)
		updateStat("highRiskEvents", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		deleteFilter := bson.M{}
		for k, v := range baseFilter {
			deleteFilter[k] = v
		}
		deleteFilter["action"] = bson.M{"$in": []string{"delete", "restore"}}
		count, _ := auditLogCollection.CountDocuments(ctx, deleteFilter)
		updateStat("deletesRestores", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		approvalFilter := bson.M{}
		for k, v := range baseFilter {
			approvalFilter[k] = v
		}
		approvalFilter["action"] = bson.M{"$regex": "approval", "$options": "i"}
		count, _ := auditLogCollection.CountDocuments(ctx, approvalFilter)
		updateStat("approvalEvents", count)
	}()

	if len(assignedAssetIDs) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assetFilter := bson.M{
				"organizationId": orgID,
				"entityType": "asset",
				"entityID": bson.M{"$in": assignedAssetIDs},
			}
			count, _ := auditLogCollection.CountDocuments(ctx, assetFilter)
			updateStat("assetEvents", count)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		riskIDs := getAnalystRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
		if len(riskIDs) > 0 {
			riskFilter := bson.M{
				"organizationId": orgID,
				"entityType": "risk",
				"entityID": bson.M{"$in": riskIDs},
			}
			count, _ := auditLogCollection.CountDocuments(ctx, riskFilter)
			updateStat("riskEvents", count)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		riskIDs := getAnalystRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
		actionIDs := getAnalystActionIDsForRisks(ctx, orgID, riskIDs)
		if len(actionIDs) > 0 {
			actionFilter := bson.M{
				"organizationId": orgID,
				"entityType": "action",
				"entityID": bson.M{"$in": actionIDs},
			}
			count, _ := auditLogCollection.CountDocuments(ctx, actionFilter)
			updateStat("actionEvents", count)
		}
	}()

	wg.Wait()
	utils.RespondWithJSON(w, http.StatusOK, stats)
}

// GetAuditStats returns statistics for admin/superadmin
func GetAuditStats(w http.ResponseWriter, r *http.Request) {
	orgIDStr, ok := r.Context().Value("orgID").(string)
	if !ok || orgIDStr == "" {
		utils.RespondWithError(w, http.StatusUnauthorized, "organization id required")
		return
	}

	orgID, err := primitive.ObjectIDFromHex(orgIDStr)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "invalid organization id")
		return
	}

	userRole, _ := r.Context().Value("userRole").(string)
	
	if userRole != "superadmin" && userRole != "admin" {
		utils.RespondWithError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	filter := bson.M{"organizationId": orgID}

	var wg sync.WaitGroup
	var mu sync.Mutex
	stats := map[string]interface{}{
		"totalEvents":      0,
		"last24Hours":      0,
		"last7Days":        0,
		"userCount":        0,
		"topActions":       []string{},
		"entityBreakdown":  map[string]int64{},
		"highRiskEvents":   0,
		"auditCompliance":  100,
	}

	updateStat := func(key string, value interface{}) {
		mu.Lock()
		stats[key] = value
		mu.Unlock()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		count, _ := auditLogCollection.CountDocuments(ctx, filter)
		updateStat("totalEvents", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
		count, _ := auditLogCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"createdAt": bson.M{"$gte": twentyFourHoursAgo},
		})
		updateStat("last24Hours", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
		count, _ := auditLogCollection.CountDocuments(ctx, bson.M{
			"organizationId": orgID,
			"createdAt": bson.M{"$gte": sevenDaysAgo},
		})
		updateStat("last7Days", count)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeline := mongo.Pipeline{
			bson.D{{Key: "$match", Value: filter}},
			bson.D{{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$userID"},
			}}},
			bson.D{{Key: "$count", Value: "userCount"}},
		}
		
		cursor, err := auditLogCollection.Aggregate(ctx, pipeline)
		if err == nil && cursor.Next(ctx) {
			var result struct {
				UserCount int64 `bson:"userCount"`
			}
			cursor.Decode(&result)
			updateStat("userCount", result.UserCount)
		}
		if cursor != nil {
			cursor.Close(ctx)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeline := mongo.Pipeline{
			bson.D{{Key: "$match", Value: filter}},
			bson.D{{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$action"},
				{Key: "count", Value: bson.D{{Key: "$sum", Value: 1}}},
			}}},
			bson.D{{Key: "$sort", Value: bson.D{{Key: "count", Value: -1}}}},
			bson.D{{Key: "$limit", Value: 5}},
		}
		
		cursor, err := auditLogCollection.Aggregate(ctx, pipeline)
		if err == nil {
			defer cursor.Close(ctx)
			var topActions []string
			for cursor.Next(ctx) {
				var result struct {
					Action string `bson:"_id"`
					Count  int64  `bson:"count"`
				}
				if err := cursor.Decode(&result); err == nil {
					topActions = append(topActions, result.Action)
				}
			}
			updateStat("topActions", topActions)
		}
	}()

	wg.Wait()
	utils.RespondWithJSON(w, http.StatusOK, stats)
}

// Helper function to convert audit logs to JSON-friendly format
func convertAuditLogsToJSON(logs []models.AuditLog) []map[string]interface{} {
	jsonLogs := make([]map[string]interface{}, len(logs))
	
	for i, log := range logs {
		jsonLog := map[string]interface{}{
			"_id":            log.ID,
			"organizationId": log.OrganizationID,
			"userID":         log.UserID,
			"userEmail":      log.UserEmail,
			"userRole":       log.UserRole,
			"entityType":     log.EntityType,
			"entityId":       log.EntityID,
			"action":         log.Action,
			"createdAt":      log.CreatedAt,
			"ipAddress":      log.IPAddress,
			"userAgent":      log.UserAgent,
		}
		
		// Convert Details to proper JSON
		if log.Details != nil {
			if bsonM, ok := log.Details.(bson.M); ok {
				detailsMap := make(map[string]interface{})
				for k, v := range bsonM {
					detailsMap[k] = v
				}
				jsonLog["details"] = detailsMap
			} else if strMap, ok := log.Details.(map[string]interface{}); ok {
				jsonLog["details"] = strMap
			} else {
				jsonLog["details"] = log.Details
			}
		}
		
		jsonLogs[i] = jsonLog
	}
	
	return jsonLogs
}

// DebugAnalystAssets for debugging
func DebugAnalystAssets(w http.ResponseWriter, r *http.Request) {
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

	userRole, _ := r.Context().Value("userRole").(string)
	
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	
	assignedAssetIDs := getAnalystAssignedAssetIDs(ctx, userID, orgID, userRole)
	
	riskIDs := getAnalystRiskIDsForAssets(ctx, orgID, assignedAssetIDs)
	actionIDs := getAnalystActionIDsForRisks(ctx, orgID, riskIDs)
	
	response := map[string]interface{}{
		"userID": userIDStr,
		"userRole": userRole,
		"orgID": orgIDStr,
		"assignedAssetCount": len(assignedAssetIDs),
		"assignedAssetIDs": assignedAssetIDs,
		"riskCount": len(riskIDs),
		"actionCount": len(actionIDs),
		"timestamp": time.Now(),
	}
	
	utils.RespondWithJSON(w, http.StatusOK, response)
}

// CreateTestAuditLog creates a test audit log for debugging
func CreateTestAuditLog(w http.ResponseWriter, r *http.Request) {
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

	userName, _ := r.Context().Value("userName").(string)
	userRole, _ := r.Context().Value("userRole").(string)

	orgID, _ := primitive.ObjectIDFromHex(orgIDStr)
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	
	audit := models.AuditLog{
		ID:             primitive.NewObjectID(),
		OrganizationID: orgID,
		UserID:         userID,
		EntityType:     "test",
		EntityID:       primitive.NewObjectID(),
		Action:         "test_action",
		Details: map[string]interface{}{
			"message":     "Test audit log created for debugging",
			"userName":    userName,
			"userRole":    userRole,
			"source":      "manual",
			"summary":     "Test audit log created",
		},
		CreatedAt:      time.Now(),
	}
	
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	
	_, err := auditLogCollection.InsertOne(ctx, audit)
	if err != nil {
		log.Printf("Error creating test audit log: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "Failed to create test audit log")
		return
	}
	
	BroadcastAudit(&audit)
	
	utils.RespondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Test audit log created successfully",
		"auditId": audit.ID.Hex(),
	})
}

// Helper function to calculate start date based on time range
func calculateStartDate(timeRange string) time.Time {
	now := time.Now()
	switch timeRange {
	case "24h", "1d":
		return now.Add(-24 * time.Hour)
	case "7d":
		return now.Add(-7 * 24 * time.Hour)
	case "30d":
		return now.Add(-30 * 24 * time.Hour)
	case "90d":
		return now.Add(-90 * 24 * time.Hour)
	case "ytd":
		return time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
	default:
		return time.Time{}
	}
}
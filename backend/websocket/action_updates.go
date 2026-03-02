package websocket

import (
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ActionUpdate represents a real-time action update
type ActionUpdate struct {
	Type      string      `json:"type"` // ACTION_CREATED, ACTION_UPDATED, ACTION_DELETED, ACTION_STATUS_CHANGE
	ActionID  string      `json:"actionId"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
	UserID    string      `json:"userId,omitempty"`
	UserName  string      `json:"userName,omitempty"`
}

// BroadcastActionUpdate sends update to all connected clients in organization
func BroadcastActionUpdate(orgID primitive.ObjectID, update ActionUpdate) {
	hub.mutex.Lock()
	defer hub.mutex.Unlock()

	if clients, ok := hub.clients[orgID.Hex()]; ok {
		data, err := json.Marshal(update)
		if err != nil {
			log.Printf("Failed to marshal action update: %v", err)
			return
		}

		for client := range clients {
			select {
			case client.send <- data:
			default:
				close(client.send)
				delete(clients, client)
			}
		}
	}
}

// SendActionCreated broadcasts new action creation
func SendActionCreated(orgID primitive.ObjectID, action interface{}, userID, userName string) {
	BroadcastActionUpdate(orgID, ActionUpdate{
		Type:      "ACTION_CREATED",
		Data:      action,
		Timestamp: time.Now(),
		UserID:    userID,
		UserName:  userName,
	})
}

// SendActionUpdated broadcasts action updates
func SendActionUpdated(orgID primitive.ObjectID, actionID string, changes interface{}, userID, userName string) {
	BroadcastActionUpdate(orgID, ActionUpdate{
		Type:      "ACTION_UPDATED",
		ActionID:  actionID,
		Data:      changes,
		Timestamp: time.Now(),
		UserID:    userID,
		UserName:  userName,
	})
}

// SendActionStatusChange broadcasts status changes
func SendActionStatusChange(orgID primitive.ObjectID, actionID string, oldStatus, newStatus string, userID, userName string) {
	BroadcastActionUpdate(orgID, ActionUpdate{
		Type:     "ACTION_STATUS_CHANGE",
		ActionID: actionID,
		Data: map[string]interface{}{
			"oldStatus": oldStatus,
			"newStatus": newStatus,
		},
		Timestamp: time.Now(),
		UserID:    userID,
		UserName:  userName,
	})
}
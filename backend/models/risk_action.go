package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RiskAction struct {
	ID           primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	RiskID       primitive.ObjectID `json:"riskId" bson:"riskId"`
	Title        string             `json:"title" bson:"title"`
	Description  string             `json:"description" bson:"description"`
	Type         string             `json:"type" bson:"type"` // preventive, corrective, recovery, etc.
	Owner        string             `json:"owner" bson:"owner"`
	DueDate      *time.Time         `json:"dueDate,omitempty" bson:"dueDate,omitempty"`
	Status       string             `json:"status" bson:"status"` // not_started, in_progress, completed, etc.
	Priority     string             `json:"priority,omitempty" bson:"priority,omitempty"`     // high, medium, low
	Cost         float64            `json:"cost,omitempty" bson:"cost,omitempty"`             // action cost
	Effectiveness float64           `json:"effectiveness,omitempty" bson:"effectiveness,omitempty"` // Changed from string to float64
	CreatedAt    time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt    time.Time          `json:"updatedAt" bson:"updatedAt"`
}
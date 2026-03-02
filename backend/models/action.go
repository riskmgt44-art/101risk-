package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Action struct {
	ID             primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	OrganizationID primitive.ObjectID `json:"organizationId" bson:"organizationId"`
	RiskID         primitive.ObjectID `json:"riskId" bson:"riskId"`
	Title          string             `json:"title" bson:"title"`
	Description    string             `json:"description,omitempty" bson:"description,omitempty"`
	Status         string             `json:"status" bson:"status"`
	Priority       string             `json:"priority,omitempty" bson:"priority,omitempty"`
	Owner          string             `json:"owner,omitempty" bson:"owner,omitempty"`
	Cost           float64            `json:"cost,omitempty" bson:"cost,omitempty"`
	Progress       int                `json:"progress,omitempty" bson:"progress,omitempty"`
	StartDate      *time.Time         `json:"startDate,omitempty" bson:"startDate,omitempty"`
	EndDate        *time.Time         `json:"endDate,omitempty" bson:"endDate,omitempty"`
	DueDate        *time.Time         `json:"dueDate,omitempty" bson:"dueDate,omitempty"` // ADD THIS LINE
	Notes          string             `json:"notes,omitempty" bson:"notes,omitempty"`
	CreatedAt      time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt      time.Time          `json:"updatedAt" bson:"updatedAt"`
}
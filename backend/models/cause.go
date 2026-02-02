package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Cause struct {
	ID          primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	RiskID      primitive.ObjectID `json:"riskId" bson:"riskId"`
	Title       string             `json:"title" bson:"title"`
	Description string             `json:"description" bson:"description"`
	Actions     []RiskAction       `json:"actions,omitempty" bson:"actions,omitempty"`
	CreatedAt   time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt   time.Time          `json:"updatedAt" bson:"updatedAt"`
}
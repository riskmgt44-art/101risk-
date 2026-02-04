// models/organization.go
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Organization struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name      string             `bson:"name" json:"name"`
	Type      string             `bson:"type" json:"type"`
	Industry  string             `bson:"industry" json:"industry"`
	Size      string             `bson:"size,omitempty" json:"size,omitempty"`
	Country   string             `bson:"country" json:"country"`
	Timezone  string             `bson:"timezone" json:"timezone"`
	CreatedAt time.Time          `bson:"createdAt" json:"createdAt"`
}
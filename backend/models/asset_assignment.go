package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AssetAssignment struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	UserID         primitive.ObjectID `bson:"userId" json:"userId"`
	AssetID        primitive.ObjectID `bson:"assetId" json:"assetId"`
	AssignedBy     primitive.ObjectID `bson:"assignedBy" json:"assignedBy"`
	AssignedAt     time.Time          `bson:"assignedAt" json:"assignedAt"`
	Role           string             `bson:"role" json:"role"` // "owner", "manager", "viewer"
	Status         string             `bson:"status" json:"status"` // "active", "inactive"
}
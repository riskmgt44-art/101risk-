// models/asset.go
package models

import (
	"time"
	
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Asset struct {
	ID               primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name             string               `bson:"name" json:"name"`
	Description      string               `bson:"description,omitempty" json:"description,omitempty"`
	Category         string               `bson:"category" json:"category"`
	Nature           string               `bson:"nature,omitempty" json:"nature,omitempty"`
	Location         string               `bson:"location,omitempty" json:"location,omitempty"`
	Owner            string               `bson:"owner,omitempty" json:"owner,omitempty"`
	OwnerUserID      *primitive.ObjectID  `bson:"ownerUserId,omitempty" json:"ownerUserId,omitempty"`
	AssignedUserIDs  []primitive.ObjectID `bson:"assignedUserIds,omitempty" json:"assignedUserIds"`
	OrganizationID   primitive.ObjectID   `bson:"organizationId" json:"organizationId"`
	Status           string               `bson:"status" json:"status"` // active, inactive, archived
	CreatedBy        primitive.ObjectID   `bson:"createdBy" json:"createdBy"`
	CreatedAt        time.Time            `bson:"createdAt" json:"createdAt"`
	UpdatedAt        time.Time            `bson:"updatedAt" json:"updatedAt"`
}
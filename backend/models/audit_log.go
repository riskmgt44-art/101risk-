// models/audit.go
package models

import (
	"time"
	
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AuditLog struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	UserID         primitive.ObjectID `bson:"userId" json:"userId"`
	UserEmail      string             `bson:"userEmail" json:"userEmail"`
	UserRole       string             `bson:"userRole" json:"userRole"`
	Action         string             `bson:"action" json:"action"`
	EntityType     string             `bson:"entityType" json:"entityType"` // risk, asset, action, user, approval
	EntityID       primitive.ObjectID `bson:"entityId" json:"entityId"`
	Details        interface{}        `bson:"details" json:"details"` // Can be string or bson.M
	IPAddress      string             `bson:"ipAddress,omitempty" json:"ipAddress,omitempty"`
	UserAgent      string             `bson:"userAgent,omitempty" json:"userAgent,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
}
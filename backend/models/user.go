package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                 primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	OrganizationID     primitive.ObjectID   `bson:"organizationId" json:"organizationId"`
	FirstName          string               `bson:"firstName" json:"firstName"`
	LastName           string               `bson:"lastName" json:"lastName"`
	Email              string               `bson:"email" json:"email"`
	JobTitle           string               `bson:"jobTitle" json:"jobTitle"`
	Phone              string               `bson:"phone,omitempty" json:"phone,omitempty"`
	Role               string               `bson:"role" json:"role"`
	PasswordHash       string               `bson:"passwordHash" json:"-"`
	Status             string               `bson:"status,omitempty" json:"status"` // active, suspended, invited
	IsActive           bool                 `bson:"isActive" json:"isActive" default:"true"`
	ActiveSessions     int                  `bson:"activeSessions" json:"activeSessions" default:"0"`
	MFAEnabled         bool                 `bson:"mfaEnabled" json:"mfaEnabled" default:"false"`
	MFASecret          string               `bson:"mfaSecret,omitempty" json:"-"`
	ResetToken         *string              `bson:"resetToken,omitempty" json:"-"`
	ResetExpire        *time.Time           `bson:"resetExpire,omitempty" json:"-"`
	LastLogin          *time.Time           `bson:"lastLogin,omitempty" json:"lastLogin"`
	LastPasswordChange *time.Time           `bson:"lastPasswordChange,omitempty" json:"lastPasswordChange"`
	CreatedAt          time.Time            `bson:"createdAt" json:"createdAt"`
	UpdatedAt          time.Time            `bson:"updatedAt" json:"updatedAt"`
	DeletedAt          *time.Time           `bson:"deletedAt,omitempty" json:"deletedAt,omitempty"`
	DeletedBy          *primitive.ObjectID  `bson:"deletedBy,omitempty" json:"deletedBy,omitempty"`
	AssignedAssetIDs   []primitive.ObjectID `bson:"assignedAssetIds,omitempty" json:"assignedAssetIds,omitempty"`
	AssetIDs           []primitive.ObjectID `bson:"assetIds,omitempty" json:"assetIds,omitempty"` // Added for compatibility
}
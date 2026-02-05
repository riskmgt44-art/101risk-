// models/approval.go
package models

import (
	"time"
	
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Approval struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Title          string             `bson:"title" json:"title"`
	Type           string             `bson:"type" json:"type"` // risk_submission, action_submission, etc.
	Status         string             `bson:"status" json:"status"` // pending, approved, rejected, cancelled
	SubmittedBy    primitive.ObjectID `bson:"submittedBy" json:"submittedBy"`
	SubmittedAt    time.Time          `bson:"submittedAt" json:"submittedAt"`
	ReviewedAt     *time.Time         `bson:"reviewedAt,omitempty" json:"reviewedAt,omitempty"`
	ApprovedAt     *time.Time         `bson:"approvedAt,omitempty" json:"approvedAt,omitempty"`
	RejectedAt     *time.Time         `bson:"rejectedAt,omitempty" json:"rejectedAt,omitempty"`
	CancelledAt    *time.Time         `bson:"cancelledAt,omitempty" json:"cancelledAt,omitempty"`
	ReviewerID     *primitive.ObjectID `bson:"reviewerId,omitempty" json:"reviewerId,omitempty"`
	OrganizationID primitive.ObjectID `bson:"organizationId" json:"organizationId"`
	RiskID         *primitive.ObjectID `bson:"riskId,omitempty" json:"riskId,omitempty"`
	ActionID       *primitive.ObjectID `bson:"actionId,omitempty" json:"actionId,omitempty"`
	Comments       string             `bson:"comments,omitempty" json:"comments,omitempty"`
	CancelReason   string             `bson:"cancelReason,omitempty" json:"cancelReason,omitempty"`
	// ADD THESE FIELDS:
	CurrentLevel   int                `bson:"currentLevel,omitempty" json:"currentLevel,omitempty"`
	TotalLevels    int                `bson:"totalLevels,omitempty" json:"totalLevels,omitempty"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	UpdatedAt      time.Time          `bson:"updatedAt" json:"updatedAt"`
}
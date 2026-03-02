package models

import (
	"time"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Risk struct {
	ID                      primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	OrganizationID          primitive.ObjectID   `bson:"organizationId" json:"organizationId"`
	AssetID                 primitive.ObjectID   `bson:"assetId,omitempty" json:"assetId,omitempty"` // Changed to omitempty
	RiskID                  string               `bson:"riskId" json:"riskId"`
	Type                    string               `bson:"type" json:"type"`
	Title                   string               `bson:"title" json:"title"`
	Description             string               `bson:"description,omitempty" json:"description,omitempty"` // Added omitempty
	Causes                  []string             `bson:"causes,omitempty" json:"causes,omitempty"`
	Event                   string               `bson:"event,omitempty" json:"event,omitempty"`
	Consequences            []string             `bson:"consequences,omitempty" json:"consequences,omitempty"`
	Status                  string               `bson:"status" json:"status"`
	RiskOwnerID             primitive.ObjectID   `bson:"riskOwnerId,omitempty" json:"riskOwnerId,omitempty"`
	RiskOwnerName           string               `bson:"riskOwnerName,omitempty" json:"riskOwnerName,omitempty"`
	SubProject              string               `bson:"subProject,omitempty" json:"subProject,omitempty"`
	NextReviewDate          *time.Time           `bson:"nextReviewDate,omitempty" json:"nextReviewDate,omitempty"`
	ExposureStartDate       *time.Time           `bson:"exposureStartDate,omitempty" json:"exposureStartDate,omitempty"`
	ExposureEndDate         *time.Time           `bson:"exposureEndDate,omitempty" json:"exposureEndDate,omitempty"`
	OccurenceLevel          string               `bson:"occurenceLevel,omitempty" json:"occurenceLevel,omitempty"`
	AuditTrailCount         int                  `bson:"auditTrailCount" json:"auditTrailCount"`
	LinkedActions           []string             `bson:"linkedActions,omitempty" json:"linkedActions,omitempty"` // Added omitempty
	ProjectRAMCurrent       string               `bson:"projectRamCurrent,omitempty" json:"projectRamCurrent,omitempty"`
	ProjectRAMTarget        string               `bson:"projectRamTarget,omitempty" json:"projectRamTarget,omitempty"`
	RiskVisualRAMCurrent    string               `bson:"riskVisualRamCurrent,omitempty" json:"riskVisualRamCurrent,omitempty"`
	RiskVisualRAMTarget     string               `bson:"riskVisualRamTarget,omitempty" json:"riskVisualRamTarget,omitempty"`
	HSSE_RAMCurrent         string               `bson:"hsseRamCurrent,omitempty" json:"hsseRamCurrent,omitempty"`
	HSSE_RAMTarget          string               `bson:"hsseRamTarget,omitempty" json:"hsseRamTarget,omitempty"`
	Manageability           string               `bson:"manageability,omitempty" json:"manageability,omitempty"`
	FunctionalAreaTECOP     string               `bson:"functionalAreaTECOP,omitempty" json:"functionalAreaTECOP,omitempty"`
	ThresholdChanging       bool                 `bson:"thresholdChanging" json:"thresholdChanging"`
	CreatedAt               time.Time            `bson:"createdAt" json:"createdAt"`
	UpdatedAt               time.Time            `bson:"updatedAt" json:"updatedAt"`
	CreatedBy               primitive.ObjectID   `bson:"createdBy,omitempty" json:"createdBy,omitempty"`
	UpdatedBy               primitive.ObjectID   `bson:"updatedBy,omitempty" json:"updatedBy,omitempty"`
	
	// NEW FIELDS that frontend expects but were missing:
	LinkedAssets            []string             `bson:"linkedAssets,omitempty" json:"linkedAssets,omitempty"`
	
	// Bowtie Analysis Fields
	BowtieCauses            []Cause              `bson:"bowtieCauses,omitempty" json:"bowtieCauses,omitempty"`
	BowtieConsequences      []Consequence        `bson:"bowtieConsequences,omitempty" json:"bowtieConsequences,omitempty"`
	
	// Additional fields for risk_bowtie_handler.go
	Department              string               `bson:"department,omitempty" json:"department,omitempty"`
	Likelihood              string               `bson:"likelihood,omitempty" json:"likelihood,omitempty"`
	Impact                  string               `bson:"impact,omitempty" json:"impact,omitempty"`
	RiskScore               float64              `bson:"riskScore,omitempty" json:"riskScore,omitempty"` // Changed from int to float64
}
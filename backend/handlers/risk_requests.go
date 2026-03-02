package handlers

// No imports needed for this file since we're just defining structs

// Bowtie request structures
type CauseRequest struct {
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Actions     []ActionRequest `json:"actions,omitempty"`
}

type ConsequenceRequest struct {
	Title       string          `json:"title"`
	Description string          `json:"description,omitempty"`
	Actions     []ActionRequest `json:"actions,omitempty"`
}

type ActionRequest struct {
	Title         string     `json:"title"`
	Description   string     `json:"description,omitempty"`
	Type          string     `json:"type"` // preventive, detective, mitigative, recovery
	Owner         string     `json:"owner"`
	DueDate       *string    `json:"dueDate,omitempty"`
	Status        string     `json:"status,omitempty"`
	Priority      string     `json:"priority,omitempty"`
	Cost          float64    `json:"cost,omitempty"`
	Effectiveness float64    `json:"effectiveness,omitempty"`
}

// Extended CreateRiskRequest with Bowtie support
type CreateRiskRequestV2 struct {
	Title                 string                `json:"title"`
	Description           string                `json:"description"`
	Type                  string                `json:"type"`
	AssetID               string                `json:"assetId,omitempty"`
	SubProject            string                `json:"subProject,omitempty"`
	Department            string                `json:"department,omitempty"`
	Status                string                `json:"status"`
	RiskOwnerName         string                `json:"riskOwnerName,omitempty"`
	NextReviewDate        *string               `json:"nextReviewDate,omitempty"`
	ExposureStartDate     *string               `json:"exposureStartDate,omitempty"`
	ExposureEndDate       *string               `json:"exposureEndDate,omitempty"`
	OccurrenceLevel       string                `json:"occurrenceLevel,omitempty"`
	Likelihood            string                `json:"likelihood,omitempty"`
	Impact                string                `json:"impact,omitempty"`
	ProjectRAMCurrent     string                `json:"projectRamCurrent,omitempty"`
	ProjectRAMTarget      string                `json:"projectRamTarget,omitempty"`
	RiskVisualRAMCurrent  string                `json:"riskVisualRamCurrent,omitempty"`
	RiskVisualRAMTarget   string                `json:"riskVisualRamTarget,omitempty"`
	HSSE_RAMCurrent       string                `json:"hsseRamCurrent,omitempty"`
	HSSE_RAMTarget        string                `json:"hsseRamTarget,omitempty"`
	Manageability         string                `json:"manageability,omitempty"`
	FunctionalAreaTECOP   string                `json:"functionalAreaTECOP,omitempty"`
	ThresholdChanging     bool                  `json:"thresholdChanging"`
	
	// For backward compatibility
	Causes                []string              `json:"causes,omitempty"`
	Consequences          []string              `json:"consequences,omitempty"`
	
	// New Bowtie structure
	BowtieCauses          []CauseRequest        `json:"bowtieCauses,omitempty"`
	BowtieConsequences    []ConsequenceRequest  `json:"bowtieConsequences,omitempty"`
}

// AnalystCreateRiskRequestV2 for analysts with Bowtie
type AnalystCreateRiskRequestV2 struct {
	Title                 string                `json:"title"`
	Description           string                `json:"description"`
	Type                  string                `json:"type"`
	AssetID               string                `json:"assetId,omitempty"`
	SubProject            string                `json:"subProject,omitempty"`
	RiskOwnerName         string                `json:"riskOwnerName,omitempty"`
	NextReviewDate        *string               `json:"nextReviewDate,omitempty"`
	ExposureStartDate     *string               `json:"exposureStartDate,omitempty"`
	ExposureEndDate       *string               `json:"exposureEndDate,omitempty"`
	OccurrenceLevel       string                `json:"occurrenceLevel,omitempty"`
	ProjectRAMCurrent     string                `json:"projectRamCurrent,omitempty"`
	ProjectRAMTarget      string                `json:"projectRamTarget,omitempty"`
	RiskVisualRAMCurrent  string                `json:"riskVisualRamCurrent,omitempty"`
	RiskVisualRAMTarget   string                `json:"riskVisualRamTarget,omitempty"`
	HSSE_RAMCurrent       string                `json:"hsseRamCurrent,omitempty"`
	HSSE_RAMTarget        string                `json:"hsseRamTarget,omitempty"`
	Manageability         string                `json:"manageability,omitempty"`
	FunctionalAreaTECOP   string                `json:"functionalAreaTECOP,omitempty"`
	ThresholdChanging     bool                  `json:"thresholdChanging"`
	
	// For backward compatibility
	Causes                []string              `json:"causes,omitempty"`
	Consequences          []string              `json:"consequences,omitempty"`
	
	// New Bowtie structure
	BowtieCauses          []CauseRequest        `json:"bowtieCauses,omitempty"`
	BowtieConsequences    []ConsequenceRequest  `json:"bowtieConsequences,omitempty"`
}

// UpdateRiskRequestV2 with Bowtie support
type UpdateRiskRequestV2 struct {
	Title                 string                `json:"title,omitempty"`
	Description           string                `json:"description,omitempty"`
	Type                  string                `json:"type,omitempty"`
	AssetID               string                `json:"assetId,omitempty"`
	SubProject            string                `json:"subProject,omitempty"`
	Department            string                `json:"department,omitempty"`
	Status                string                `json:"status,omitempty"`
	RiskOwnerName         string                `json:"riskOwnerName,omitempty"`
	NextReviewDate        *string               `json:"nextReviewDate,omitempty"`
	ExposureStartDate     *string               `json:"exposureStartDate,omitempty"`
	ExposureEndDate       *string               `json:"exposureEndDate,omitempty"`
	OccurrenceLevel       string                `json:"occurrenceLevel,omitempty"`
	Likelihood            string                `json:"likelihood,omitempty"`
	Impact                string                `json:"impact,omitempty"`
	ProjectRAMCurrent     string                `json:"projectRamCurrent,omitempty"`
	ProjectRAMTarget      string                `json:"projectRamTarget,omitempty"`
	RiskVisualRAMCurrent  string                `json:"riskVisualRamCurrent,omitempty"`
	RiskVisualRAMTarget   string                `json:"riskVisualRamTarget,omitempty"`
	HSSE_RAMCurrent       string                `json:"hsseRamCurrent,omitempty"`
	HSSE_RAMTarget        string                `json:"hsseRamTarget,omitempty"`
	Manageability         string                `json:"manageability,omitempty"`
	FunctionalAreaTECOP   string                `json:"functionalAreaTECOP,omitempty"`
	ThresholdChanging     *bool                 `json:"thresholdChanging,omitempty"`
	
	// For backward compatibility
	Causes                []string              `json:"causes,omitempty"`
	Consequences          []string              `json:"consequences,omitempty"`
	LinkedAssets          []string              `json:"linkedAssets,omitempty"`
	LinkedActions         []string              `json:"linkedActions,omitempty"`
	
	// New Bowtie structure
	BowtieCauses          []CauseRequest        `json:"bowtieCauses,omitempty"`
	BowtieConsequences    []ConsequenceRequest  `json:"bowtieConsequences,omitempty"`
}
package domain

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

type Metadata struct {
	Progress string                 `json:"progress"`
	Service  enums.EventSubjectName `json:"service"`
}

type StatusHost struct {
	Host     string     `json:"id,omitempty"`
	Metadata []Metadata `json:"metadata,omitempty"`
}

type ResultHost struct {
	Host string `json:"id,omitempty"`
}

type Scan struct {
	ID              uuid.UUID      `json:"id,omitempty" db:"id"`
	TenantID        uuid.UUID      `json:"tenant_id,omitempty"`
	OperatorID      uuid.UUID      `json:"operator_id,omitempty"`
	HostID          uuid.UUID      `json:"host_ids,omitempty"`
	Target          results.Target `json:"targets"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	StartedAt       time.Time      `json:"started_at"`
	EndedAt         *time.Time     `json:"ended_at"`
	Status          string         `json:"status,omitempty"`
	ProtectionScore *float64       `json:"protection_score"`
}

type ScanSummary struct {
	ScanID          uuid.UUID            `json:"scan_id,omitempty"`
	ScanDate        string               `json:"scan_date,omitempty"`
	Host            string               `json:"host,omitempty"`
	Vulnerabilities int                  `json:"vulnerabilities"`
	Severities      tools.SeverityCounts `json:"severities,omitempty"`
	Duration        int32                `json:"duration,omitempty"`
	Status          string               `json:"status,omitempty"`
}

type ScanResult struct {
	ScanID    uuid.UUID
	ToolName  string
	Success   bool
	Result    tools.ToolResult
	CreatedAt time.Time `json:"created_at"`
}

type ScanOSandServicesResult struct {
	AssetType                 string    `json:"asset_type"`
	ID                        int32     `json:"id"`
	HostID                    uuid.UUID `json:"host_id"`
	ScanID                    uuid.UUID `json:"scan_id"`
	Name                      string    `json:"name"`
	Version                   string    `json:"version"`
	Family                    string    `json:"family"`
	OsType                    string    `json:"os_type"`
	Port                      int32     `json:"port"`
	Protocol                  string    `json:"protocol"`
	Fingerprint               string    `json:"fingerprint"`
	Cpe                       string    `json:"cpe"`
	Product                   string    `json:"product"`
	Accuracy                  int32     `json:"accuracy"`
	PortState                 string    `json:"port_state"`
	TotalVulnerabilitiesCount int64     `json:"total_vulnerabilities_count"`
	CriticalCount             int64     `json:"critical_count"`
	HighCount                 int64     `json:"high_count"`
	MediumCount               int64     `json:"medium_count"`
	LowCount                  int64     `json:"low_count"`
	NoneCount                 int64     `json:"none_count"`
	UnknownCount              int64     `json:"unknown_count"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

type Tool struct {
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	Type        int       `json:"type,omitempty"`
}

// ScanInsightsBaseData serves as an intermediary between the domain and repository layer.
type ScanInsightsBaseData struct {
	ScanID                  uuid.UUID
	HostAlias               string
	ScanDate                time.Time
	TotalVulnerabilities    int
	CriticalVulnerabilities int
	HighVulnerabilities     int
	MediumVulnerabilities   int
	LowVulnerabilities      int
	NoneVulnerabilities     int
	UnknownVulnerabilities  int
	SeverityPerTypeJSON     []byte
}

// ScanInsights is the comprehensive struct containing all calculated insights for a scan.
type ScanInsights struct {
	ProtectionScore          float64              `json:"protection_score"`
	SeverityCounts           tools.SeverityCounts `json:"severity_counts"`
	SeverityPerType          map[string]string    `json:"severity_per_type"`
	TotalVulnerabilities     int                  `json:"total_vulnerabilities"`
	VulnerabilityVariation   int                  `json:"vulnerability_variation"`
	ProtectionScoreVariation float64              `json:"protection_score_variation"`
	Metadata                 ScanInsightsMetadata `json:"metadata"`
}

// ScanInsightsMetadata holds basic identifying information for the scan insights.
type ScanInsightsMetadata struct {
	ScanID    uuid.UUID `json:"scan_id"`
	HostAlias string    `json:"host_alias"`
	ScanDate  time.Time `json:"scan_date"`
}

// ScanVulnerabilitySummaryData represents the vulnerability summary data
// as returned by the service layer. This is distinct from the API response DTO.
type ScanVulnerabilitySummaryData struct {
	ScanID               uuid.UUID
	Domain               string
	TotalVulnerabilities int
	SeverityCounts       tools.SeverityCounts
	CategoryData         []ServiceCategoryData
	VulnerabilityTrends  ServiceVulnerabilityTrends
}

type ServiceCategoryData struct {
	Category string
	Count    int
}

type ServiceVulnerabilityTrends struct {
	TimePeriods               []ServiceTimePeriod
	AverageVulnerabilityCount float64
}

type ServiceTimePeriod struct {
	TimePeriod         string `json:"time_period"`
	VulnerabilityCount *int   `json:"vulnerability_count"`
}

func NewScan(hostID, tenantID, operatorID uuid.UUID, startedAt *time.Time) *Scan {
	if startedAt == nil {
		now := time.Now()
		startedAt = &now
	}

	return &Scan{
		ID:        uuid.New(),
		Status:    enums.StatusPending.String(),
		StartedAt: startedAt.UTC(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func NewScanResult(scanID uuid.UUID, result tools.ToolResult) *ScanResult {
	success := result.Err == nil

	return &ScanResult{
		ScanID:    scanID,
		Success:   success,
		Result:    result,
		CreatedAt: time.Now().UTC(),
	}
}

func (s *Scan) IsFailedOrCancelled() bool {
	return s.Status == enums.StatusFailed.String() || s.Status == enums.StatusCancelled.String()
}

func (s *Scan) IsFinished() bool {
	return s.Status == enums.StatusFailed.String() ||
		s.Status == enums.StatusCancelled.String() ||
		s.Status == enums.StatusCompleted.String()
}

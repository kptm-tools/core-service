package domain

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
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
	ID           uuid.UUID      `json:"id,omitempty" db:"id"`
	TenantID     string         `json:"tenant_id,omitempty"`
	OperatorID   string         `json:"operator_id,omitempty"`
	HostID       int            `json:"host_ids,omitempty"`
	HostsStatus  []StatusHost   `json:"hosts_status,omitempty"`
	HostsResults []ResultHost   `json:"hosts_results,omitempty"`
	Target       results.Target `json:"targets,omitempty"`
	CreatedAt    time.Time      `json:"created_at,omitempty"`
	UpdatedAt    time.Time      `json:"updated_at,omitempty"`
	StartedAt    time.Time      `json:"started_at"`
	EndedAt      *time.Time     `json:"ended_at"`
	Status       string         `json:"status,omitempty"`
}

type ScanSummary struct {
	ScanID          uuid.UUID              `json:"scan_id,omitempty"`
	ScanDate        string                 `json:"scan_date,omitempty"`
	Host            string                 `json:"host,omitempty"`
	Vulnerabilities int                    `json:"vulnerabilities"`
	Severities      results.SeverityCounts `json:"severities,omitempty"`
	Duration        float64                `json:"duration,omitempty"`
	Status          string                 `json:"status,omitempty"`
}

type ScanResult struct {
	ScanID    uuid.UUID
	ToolName  string
	Success   bool
	Result    results.ToolResult
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type Tool struct {
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	Type        int       `json:"type,omitempty"`
}

type ScanInsights struct {
	ProtectionScore          float64                `json:"protection_score"`
	SeverityCounts           results.SeverityCounts `json:"severity_counts"`
	SeverityPerType          map[string]int         `json:"severity_per_type"`
	TotalVulnerabilities     int                    `json:"total_vulnerabilities"`
	VulnerabilityVariation   int                    `json:"vulnerability_variation"`
	ProtectionScoreVariation float64                `json:"protection_score_variation"`
	Metadata                 ScanInsightsMetadata   `json:"metadata"`
}

type ScanInsightsMetadata struct {
	ScanID    uuid.UUID `json:"scan_id"`
	HostAlias string    `json:"host_alias"`
	ScanDate  time.Time `json:"scan_date"`
}

func NewScan() *Scan {
	return &Scan{
		ID:        uuid.New(),
		Status:    enums.StatusPending.String(),
		StartedAt: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func NewScanResult(scanID uuid.UUID, result results.ToolResult) *ScanResult {
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

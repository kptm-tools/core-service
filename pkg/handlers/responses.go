package handlers

import (
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type RegisterTenantResponse struct {
	ApplicationID string      `json:"application_id"`
	User          domain.User `json:"user"`
}

type ScanVulnerabilitySummaryResponse struct {
	ScanID         uuid.UUID                   `json:"scan_id"`
	Domain         string                      `json:"domain"`
	GenearlSummary VulnerabilityGeneralSummary `json:"general_summary"`
}

type VulnerabilityGeneralSummary struct {
	TotalVulnerabilities      int                       `json:"total_vulnerabilites"`
	SeverityCounts            tools.SeverityCounts      `json:"severity_counts,omitempty"`
	VulnerabilitiesByCategory VulnerabilitiesByCategory `json:"vulnerabilities_by_category"`
	VulnerabilityTrends       VulnerabilityTrends       `json:"vulnerability_trends"`
}

type VulnerabilitiesByCategory struct {
	CategoryData []CategoryData `json:"category_data"`
}

type CategoryData struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

type VulnerabilityTrends struct {
	TimePeriods               []TimePeriod `json:"time_periods"`
	AverageVulnerabilityCount float64      `json:"average_vlnearbility_count"`
}

type TimePeriod struct {
	TimePeriod         string `json:"time_period"`
	VulnerabilityCount int    `json:"vulnerability_count"`
}

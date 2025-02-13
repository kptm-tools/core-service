package handlers

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type RegisterTenantResponse struct {
	ApplicationID string      `json:"application_id"`
	User          domain.User `json:"user"`
}

type ScanVulnerabilitySummaryResponse struct {
	ScanID         string                      `json:"scan_id"`
	Domain         string                      `json:"domain"`
	GeneralSummary VulnerabilityGeneralSummary `json:"general_summary"`
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

func adaptCategoryData(serviceCategoryData []domain.ServiceCategoryData) []CategoryData {
	adaptedData := make([]CategoryData, len(serviceCategoryData))
	for i, svcData := range serviceCategoryData {
		adaptedData[i] = CategoryData{
			Category: svcData.Category,
			Count:    svcData.Count,
		}
	}
	return adaptedData
}

func adaptTimePeriods(serviceTimePeriodData []domain.ServiceTimePeriod) []TimePeriod {
	adaptedData := make([]TimePeriod, len(serviceTimePeriodData))
	for i, svcData := range serviceTimePeriodData {
		adaptedData[i] = TimePeriod{
			TimePeriod:         svcData.TimePeriod,
			VulnerabilityCount: svcData.VulnerabilityCount,
		}
	}
	return adaptedData
}

type ReportsResponse struct {
	ScanID          string    `json:"scan_id"`
	Domain          string    `json:"domain"`
	IP              string    `json:"ip"`
	ScanDate        time.Time `json:"scan_date"`
	TotalSeverities int       `json:"total_severities"`
	CommentStatus   string    `json:"comment_status"`
}

// ScoreCardTrendResponse is the DTO for the scorecard trend data for a single host
type ScoreCardTrendResponse struct {
	Alias            string   `json:"alias" example:"Ovofinance 2"`
	OldestScore      *float64 `json:"oldest_score" example:"71.0"`
	LatestScore      *float64 `json:"latest_score" example:"0.59"`
	LatestScoreGrade *string  `json:"latest_score_grade"`
}

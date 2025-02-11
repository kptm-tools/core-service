package handlers

import (
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

package domain

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
)

type TimePeriodFilter string

const (
	TimePeriodFilterMonth    TimePeriodFilter = "Month"
	TimePeriodFilterQuarter  TimePeriodFilter = "Quarter"
	TimePeriodFilterSemester TimePeriodFilter = "Semester"
)

func (t TimePeriodFilter) String() string {
	return string(t)
}

// ParseTimePeriodFilter parses a string into a TimePeriodFilter enum.
// It returns an error if the string is not a valid TimePeriodFilter value.
func ParseTimePeriodFilter(s string) (TimePeriodFilter, error) {
	switch s {
	case "Month":
		return TimePeriodFilterMonth, nil
	case "Quarter":
		return TimePeriodFilterQuarter, nil
	case "Semester":
		return TimePeriodFilterSemester, nil
	default:
		return TimePeriodFilterMonth, customerrors.ErrInvalidTimePeriodFilter
	}
}

// GetOrderedTimePeriods returns a slice of ordered time periods based on the TimePeriodFilter
func (t TimePeriodFilter) GetOrderedTimePeriods() []string {
	switch t {
	case TimePeriodFilterMonth:
		return getMonthsInOrder()
	case TimePeriodFilterQuarter:
		return getQuartersInOrder()
	case TimePeriodFilterSemester:
		return getSemestersInOrder()
	default:
		return getMonthsInOrder()
	}
}

func getMonthsInOrder() []string {
	return []string{
		"January", "February", "March", "April", "May", "June",
		"July", "August", "September", "October", "November", "December",
	}
}

func getQuartersInOrder() []string {
	return []string{"Q1", "Q2", "Q3", "Q4"}
}

func getSemestersInOrder() []string {
	return []string{"Semester 1", "Semester 2"}
}

type TenantDashboardData struct {
	OverallSecurityPosture           OverallSecurityPostureData   `json:"overall_security_posture"`
	HostSeverityHeatMap              []HostAliasSeverityCountPair `json:"host_severity_heat_map"`
	VulnerabilityTrends              []ServiceTimePeriod          `json:"vulnerability_trends"`
	LastScan                         *LastScanData                `json:"last_scan"`
	HostsWithGreatestVulnerabilities []HostAliasVulnerabilityPair `json:"hosts_with_greatest_vulnerabilities"`
}

type OverallSecurityPostureData struct {
	Score     float64 `json:"score"`
	Variation float64 `json:"variation"`
}

type LastScanData struct {
	HostAlias                     string               `json:"host_alias"`
	TotalVulnerabilities          int                  `json:"total_vulnerabilities"`
	TotalVulnerabilitiesVariation int                  `json:"total_vulnerabilities_variation"`
	SeverityCounts                tools.SeverityCounts `json:"severity_counts"`
	ScanDate                      time.Time            `json:"scan_date"`
}

// HostAliasSeverityCountPair is a struct where keys are hostnames (strings)
// and values are tools.SeverityCounts, representing vulnerability counts
// per severity.
type HostAliasSeverityCountPair struct {
	Alias         string               `json:"alias"`
	SeverityCount tools.SeverityCounts `json:"severity_count"`
}

// HostAliasVulnerabilityPair is a struct where keys are hostnames (strings)
// and values represent total vulnerability counts for the latest scan in that host.
type HostAliasVulnerabilityPair struct {
	Alias              string `json:"alias"`
	VulnerabilityCount int    `json:"vulnerability_count"`
}

type VulnerabilityAggregatesResult struct {
	TotalVulnerabilities int
	SeverityCounts       tools.SeverityCounts
}

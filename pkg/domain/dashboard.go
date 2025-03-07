package domain

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
)

type TenantDashboardData struct {
	OverallSecurityPosture           OverallSecurityPostureData
	HostSeverityHeatMap              HostSeverityHeatMapData
	VulnerabilityTrends              []ServiceTimePeriod
	LastScan                         *LastScanData
	VulnerabilitySeverityCount       tools.SeverityCounts
	HostsWithGreatestVulnerabilities []HostAliasVulnerabilityPair
}

type OverallSecurityPostureData struct {
	Score     float64
	Variation float64
}

type LastScanData struct {
	HostAlias                     string
	TotalVulnerabilities          int
	TotalVulnerabilitiesVariation int
	SeverityCounts                tools.SeverityCounts
	ScanDate                      time.Time
}

// HostSeverityHeatMapData is a map where keys are hostnames (strings)
// and values are tools.SeverityCounts, representing vulnerability counts
// per severity.
type HostSeverityHeatMapData map[string]tools.SeverityCounts

type HostAliasVulnerabilityPair struct {
	Alias              string
	VulnerabilityCount int
}

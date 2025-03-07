package domain

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
)

type TenantDashboardData struct {
	OverallSecurityPosture           OverallSecurityPostureData
	HostSeverityHeatMap              []HostAliasSeverityCountPair
	VulnerabilityTrends              []ServiceTimePeriod
	LastScan                         *LastScanData
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

// HostAliasSeverityCountPair is a struct where keys are hostnames (strings)
// and values are tools.SeverityCounts, representing vulnerability counts
// per severity.
type HostAliasSeverityCountPair struct {
	Alias         string
	SeverityCount tools.SeverityCounts
}

// HostAliasSeverityVulnerabilityPair is a struct where keys are hostnames (strings)
// and values represent total vulnerability counts for the latest scan in that host.
type HostAliasVulnerabilityPair struct {
	Alias              string
	VulnerabilityCount int
}

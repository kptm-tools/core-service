package domain

import "github.com/kptm-tools/common/common/pkg/results/tools"

// HostSeverityHeatMapData is a map where keys are hostnames (strings)
// and values are tools.SeverityCounts, representing vulnerability counts
// per severity.
type HostSeverityHeatMapData map[string]tools.SeverityCounts

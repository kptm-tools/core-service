package dto

import (
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type CreateScanParams struct {
	HostID     uuid.UUID
	TenantID   uuid.UUID
	OperatorID uuid.UUID
	ScheduleAt *string
	Frequency  *domain.RepeatSchedule
}

// VulnerabilityAggregatesParams are the params used to filter vulnerability aggregates
type VulnerabilityAggregatesParams struct {
	ScanID          uuid.UUID
	SeverityFilters []string // Empty slice means no severity filter
}

// VulnerabilityCategoriesParams are the params used to get the
// vulnerability categories of a scan.
type VulnerabilityCategoriesParams struct {
	ScanID          uuid.UUID
	SeverityFilters []string
}

// VulnerabilityTrendsParams are the params used to get the vulnerability
// trends for a particular host.
type VulnerabilityTrendsParams struct {
	HostID           uuid.UUID
	TimePeriodFilter domain.TimePeriodFilter
	SeverityFilters  []string
}

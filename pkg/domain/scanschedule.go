package domain

import (
	"time"

	"github.com/google/uuid"
)

type PeriodEnum string

const (
	Day PeriodEnum = "Day"

	Month PeriodEnum = "Month"

	Week PeriodEnum = "Week"

	Year PeriodEnum = "Year"
)

type RepeatSchedule struct {
	Quantity        int        `json:"quantity"`
	UnitOfFrequency PeriodEnum `json:"unit_of_frequency"`
}

type ScanScheduleSummary struct {
	ID            int       `json:"id"`
	CreatedDate   time.Time `json:"created_date"`
	HostAlias     string    `json:"host"`
	Frequency     string    `json:"frequency"`
	ScheduledDate time.Time `json:"scheduled_date"`
}

// ScanSchedule represents a scheduled scan in the domain
type ScanSchedule struct {
	ID             int32       `json:"id"`
	ScanID         uuid.UUID   `json:"scan_id"`
	HostID         uuid.UUID   `json:"host_id"`
	LastRunDate    *time.Time  `json:"last_run_date,omitempty"`
	ScheduledDate  *time.Time  `json:"scheduled_date,omitempty"`
	PeriodName     *PeriodEnum `json:"period_name,omitempty"`
	PeriodQuantity *int32      `json:"period_quantity,omitempty"`
	Enabled        bool        `json:"enabled"`
	HasPeriod      bool        `json:"has_period"`
	CronExpression string      `json:"cron_expression"`
	CronJobID      *int64      `json:"cron_job_id,omitempty"`
	CreatedAt      *time.Time  `json:"created_at,omitempty"`
	UpdatedAt      *time.Time  `json:"updated_at,omitempty"`
}

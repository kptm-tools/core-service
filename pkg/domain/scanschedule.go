package domain

import "time"

type ScheduleFrequency string

const (
	Day ScheduleFrequency = "Day"

	Month ScheduleFrequency = "Month"

	Week ScheduleFrequency = "Week"

	Year ScheduleFrequency = "Year"
)

type RepeatSchedule struct {
	Quantity        int               `json:"quantity"`
	UnitOfFrequency ScheduleFrequency `json:"unit_of_frequency"`
}

type ScanScheduleSummary struct {
	ID            int       `json:"id"`
	CreatedDate   time.Time `json:"created_date"`
	HostAlias     string    `json:"host"`
	Frequency     string    `json:"frequency"`
	ScheduledDate time.Time `json:"scheduled_date"`
}

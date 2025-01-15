package domain

import (
	"github.com/kptm-tools/common/common/enums"
	events "github.com/kptm-tools/common/common/events"
	"time"
)

type Metadata struct {
	Progress string            `json:"progress"`
	Service  enums.ServiceName `json:"service"`
}

type StatusHost struct {
	Host     string     `json:"id,omitempty"`
	Metadata []Metadata `json:"metadata,omitempty"`
}

type ResultHost struct {
	Host string `json:"id,omitempty"`
}

type Scan struct {
	ID           string          `json:"id,omitempty"`
	TenantID     string          `json:"tenant_id,omitempty"`
	OperatorID   string          `json:"operator_id,omitempty"`
	HostIDs      []int           `json:"host_ids,omitempty"`
	HostsStatus  []StatusHost    `json:"hosts_status,omitempty"`
	HostsResults []ResultHost    `json:"hosts_results,omitempty"`
	Targets      []events.Target `json:"targets,omitempty"`
	CreatedAt    time.Time       `json:"created_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	EndedAt      time.Time       `json:"ended_at"`
}

type ScanSummary struct {
	ScanDate      string `json:"scan_date,omitempty"`
	Host          string `json:"host,omitempty"`
	Vulnerability int    `json:"vulnerability,omitempty"`
	Severity      []int  `json:"severity,omitempty"`
	Duration      int    `json:"duration,omitempty"`
	Status        int    `json:"status,omitempty"`
}

func NewScan() *Scan {
	return &Scan{
		StartedAt: time.Now().UTC(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

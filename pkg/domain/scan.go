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
	StartedAt    time.Time       `json:"started_at"`
	EndedAt      time.Time       `json:"ended_at"`
}

func NewScan() *Scan {
	return &Scan{
		StartedAt: time.Now().UTC(),
		EndedAt:   time.Now().UTC(),
	}
}

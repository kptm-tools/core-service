package domain

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	events "github.com/kptm-tools/common/common/events"
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
	HostsStatus  []StatusHost    `json:"hosts_status,omitempty"`
	HostsResults []ResultHost    `json:"hosts_results,omitempty"`
	Targets      []events.Target `json:"targets,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

func NewScan() *Scan {
	return &Scan{
		ID:        uuid.NewString(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

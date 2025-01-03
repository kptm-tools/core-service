package domain

import (
	"github.com/google/uuid"
	res "github.com/kptm-tools/common/common/events"
	"time"
)

type Metadata struct {
	Progress string `json:"progress"`
	Service  string `json:"service"`
}

type StatusHost struct {
	Host     string      `json:"id,omitempty"`
	Metadata []*Metadata `json:"metadata,omitempty"`
}

type ResultHost struct {
	Host string `json:"id,omitempty"`
}
type Scan struct {
	ID           string       `json:"id,omitempty"`
	HostsStatus  []StatusHost `json:"hosts_status,omitempty"`
	HostsResults []ResultHost `json:"hosts_results,omitempty"`
	Targets      []res.Target `json:"targets,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

func NewScan() *Scan {
	return &Scan{
		ID:        uuid.NewString(),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

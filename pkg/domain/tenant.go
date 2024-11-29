package domain

import (	
	"time"
)

type Tenant struct {
	ID         string     `json:"id"`
	ProviderID   string     `json:"provider_id"`
	ApplicationID string     `json:"application_id"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func NewTenant(tenantID string, appID string) *Tenant {
	return &Tenant{
		ProviderID:   tenantID,
		ApplicationID: appID,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
}
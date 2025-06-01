package domain

import (
	"time"

	"github.com/google/uuid"
)

type Credential struct {
	ID       int    `json:"id,omitempty"`
	HostID   string `json:"host_id,omitempty"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Rapporteur struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	IsPrincipal bool   `json:"is_principal"`
}

type Host struct {
	ID          uuid.UUID    `json:"id,omitempty"`
	TenantID    uuid.UUID    `json:"tenant_id"`
	OperatorID  uuid.UUID    `json:"user_id"`
	Name        string       `json:"name"`
	Domain      string       `json:"domain"`
	IP          string       `json:"ip"`
	Credentials []Credential `json:"credentials"`
	Rapporteurs []Rapporteur `json:"rapporteurs"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type DomainIPResult struct {
	Domain string
	IP     string
}

func NewHost(
	domain string,
	ip string,
	tenantID, operatorID uuid.UUID,
	name string,
	credentials []Credential,
	rappporteurs []Rapporteur,
) *Host {
	return &Host{
		TenantID:    tenantID,
		OperatorID:  operatorID,
		Name:        name,
		Domain:      domain,
		IP:          ip,
		Credentials: credentials,
		Rapporteurs: rappporteurs,
	}
}

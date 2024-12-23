package domain

import (
	"time"
)

type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Rapporteur struct {
	Username    string `json:"name"`
	Password    string `json:"email"`
	IsPrincipal bool   `json:"is_principal"`
}

type Host struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	OperatorID  string    `json:"user_id"`
	Name        string    `json:"name"`
	Domain      string    `json:"domain"`
	Ip          string    `json:"ip"`
	Credentials []byte    `json:"credentials"`
	Rapporteurs []byte    `json:"rapporteurs"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type HostResponse struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Domain      string       `json:"domain"`
	Ip          string       `json:"ip"`
	Credentials []Credential `json:"credentials"`
	Rapporteurs []Rapporteur `json:"rapporteurs"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

func NewHost(domain string, ip string, tenantID string, operatorID string, name string, credentials []byte, rappporteurs []byte) *Host {
	return &Host{
		TenantID:    tenantID,
		OperatorID:  operatorID,
		Name:        name,
		Domain:      domain,
		Ip:          ip,
		Credentials: credentials,
		Rapporteurs: rappporteurs,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
}

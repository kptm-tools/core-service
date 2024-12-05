package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITenantService interface {
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
}

type ITenantHandlers interface {
	//CreateTenant(w http.ResponseWriter, req *http.Request) error
	GetTenants(w http.ResponseWriter, req *http.Request) error
}

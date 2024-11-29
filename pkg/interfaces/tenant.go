package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITenantService interface {
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
}

type ITenantHandlers interface {
	CreateTenant(w http.ResponseWriter, req *http.Request) error
	GetTenant(w http.ResponseWriter, req *http.Request) error
}


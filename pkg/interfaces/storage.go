package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IStorage interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantID(string) ([]*domain.Host, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
}

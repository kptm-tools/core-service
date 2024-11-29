package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IStorage interface {
	CreateTarget(*domain.Target) (*domain.Target, error)
	GetTargetsByTenantID(string) ([]*domain.Target, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
}

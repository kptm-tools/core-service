package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IStorage interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantIDAndUserID(string, string) ([]*domain.Host, error)
	GetHostByID(int) (*domain.Host, error)
	DeleteHostByID(int) (bool, error)
	PatchHostByID(*domain.Host) (*domain.Host, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	Ping() error
	CreateScan(*domain.Scan) (*domain.Scan, error)
	ExistAlias(string) (bool, error)
	GetScans() ([]*domain.Scan, error)
}

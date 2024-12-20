package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IStorage interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantIDAndUserID(string, string) ([]*domain.Host, error)
	GetHostByID(string) (*domain.Host, error)
	DeleteHostByID(string) (bool, error)
	PatchHostByID(ID, domainName, ip, alias string, credential, rapporteur []byte) (*domain.Host, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	Ping() error
}

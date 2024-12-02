package services

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type TenantService struct {
	storage interfaces.IStorage
}

var _ interfaces.ITenantService = (*TenantService)(nil)

func NewTenantService(storage interfaces.IStorage) *TenantService {
	return &TenantService{
		storage: storage,
	}
}

func (s *TenantService) CreateTenant(t *domain.Tenant) (*domain.Tenant, error) {

	return s.storage.CreateTenant(t)
}
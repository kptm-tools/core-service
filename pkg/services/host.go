package services

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type HostService struct {
	storage interfaces.IStorage
}

var _ interfaces.IHostService = (*HostService)(nil)

func NewHostService(storage interfaces.IStorage) *HostService {
	return &HostService{
		storage: storage,
	}
}

func (s *HostService) CreateHost(t *domain.Host) (*domain.Host, error) {

	return s.storage.CreateHost(t)
}

func (s *HostService) GetHostsByTenantID(tenantID string) ([]*domain.Host, error) {

	// hosts := &[]domain.Host{
	//
	// 	{
	// 		ID:         "1",
	// 		TenantID:   "fcde6d34-ac73-4f29-8e48-bdc5670e1d69",
	// 		OperatorID: "74eb9201-2926-40bb-9f8c-a3a52b3b5db7",
	// 		Value:      "www.facebook.com",
	// 		Type:       domain.HostType(domain.Domain),
	// 		CreatedAt:  time.Now().UTC(),
	// 		UpdatedAt:  time.Now().UTC(),
	// 	},
	// 	{
	// 		ID:         "2",
	// 		TenantID:   "fcde6d34-ac73-4f29-8e48-bdc5670e1d69",
	// 		OperatorID: "74eb9201-2926-40bb-9f8c-a3a52b3b5db7",
	// 		Value:      "www.google.com",
	// 		Type:       domain.HostType(domain.Domain),
	// 		CreatedAt:  time.Now().UTC(),
	// 		UpdatedAt:  time.Now().UTC(),
	// 	},
	// }

	hosts, err := s.storage.GetHostsByTenantID(tenantID)

	if err != nil {
		return nil, err
	}

	return hosts, nil
}

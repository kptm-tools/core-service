package services

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type TargetService struct {
	storage interfaces.IStorage
}

var _ interfaces.ITargetService = (*TargetService)(nil)

func NewTargetService(storage interfaces.IStorage) *TargetService {
	return &TargetService{
		storage: storage,
	}
}

func (s *TargetService) GetTargetsByTenantID(tenantID string) ([]*domain.Target, error) {

	// targets := &[]domain.Target{
	//
	// 	{
	// 		ID:         "1",
	// 		TenantID:   "fcde6d34-ac73-4f29-8e48-bdc5670e1d69",
	// 		OperatorID: "74eb9201-2926-40bb-9f8c-a3a52b3b5db7",
	// 		Value:      "www.facebook.com",
	// 		Type:       domain.TargetType(domain.Domain),
	// 		CreatedAt:  time.Now().UTC(),
	// 		UpdatedAt:  time.Now().UTC(),
	// 	},
	// 	{
	// 		ID:         "2",
	// 		TenantID:   "fcde6d34-ac73-4f29-8e48-bdc5670e1d69",
	// 		OperatorID: "74eb9201-2926-40bb-9f8c-a3a52b3b5db7",
	// 		Value:      "www.google.com",
	// 		Type:       domain.TargetType(domain.Domain),
	// 		CreatedAt:  time.Now().UTC(),
	// 		UpdatedAt:  time.Now().UTC(),
	// 	},
	// }

	targets, err := s.storage.GetTargetsByTenantID(tenantID)

	if err != nil {
		return nil, err
	}

	return targets, nil
}

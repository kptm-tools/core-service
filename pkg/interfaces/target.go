package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITargetService interface {
	GetTargetsByTenantID(tenantID string) ([]*domain.Target, error)
}

type ITargetHandlers interface {
	GetTargetsByTenantID(w http.ResponseWriter, req *http.Request) error
}

type IStorage interface {
	CreateTarget(*domain.Target) (*domain.Target, error)
	GetTargetsByTenantID(string) ([]*domain.Target, error)
}

package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITargetService interface {
	CreateTarget(*domain.Target) (*domain.Target, error)
	GetTargetsByTenantID(tenantID string) ([]*domain.Target, error)
}

type ITargetHandlers interface {
	CreateTarget(w http.ResponseWriter, req *http.Request) error
	GetTargetsByTenantID(w http.ResponseWriter, req *http.Request) error
}


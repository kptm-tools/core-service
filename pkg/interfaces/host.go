package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type IHostService interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantID(tenantID string) ([]*domain.Host, error)
}

type IHostHandlers interface {
	CreateHost(w http.ResponseWriter, req *http.Request) error
	GetHostsByTenantID(w http.ResponseWriter, req *http.Request) error
}

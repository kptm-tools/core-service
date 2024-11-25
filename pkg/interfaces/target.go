package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITargetService interface {
	GetAllTargets(tenantID string) (*[]domain.Target, error)
}

type ITargetHandlers interface {
	GetAllTargets(w http.ResponseWriter, req *http.Request) error
}

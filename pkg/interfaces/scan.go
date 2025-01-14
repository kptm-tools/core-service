package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"net/http"
)

type IScanService interface {
	CreateScans(hostIDs []int, tenantID, operatorID string) (*domain.Scan, error)
	GetScans() ([]*domain.Scan, error)
}

type IScanHandlers interface {
	CreateScans(writer http.ResponseWriter, request *http.Request) error
	GetScans(writer http.ResponseWriter, request *http.Request) error
}

package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"net/http"
)

type IScanService interface {
	CreateScans(hostIDs []int) (*domain.Scan, error)
}

type IScanHandlers interface {
	CreateScans(writer http.ResponseWriter, request *http.Request) error
	CancelScanByID(w http.ResponseWriter, r *http.Request) error
}

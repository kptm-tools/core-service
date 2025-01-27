package interfaces

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IScanService interface {
	CreateScans(hostIDs []int, tenantID, operatorID string) ([]*domain.Scan, error)
	GetScans(string) ([]*domain.ScanSummary, error)
	InsertScanResult(*domain.ScanResult) error
	InsertVulnerabilityResult(*domain.ScanResult) error
	UpdateScanStatus(scanID uuid.UUID, status enums.ScanStatus) error
	MarkScanAsFailed(scanID uuid.UUID) error
	MarkScanAsCancelled(scanID uuid.UUID) error
}

type IScanHandlers interface {
	CreateScans(writer http.ResponseWriter, request *http.Request) error
	GetScans(writer http.ResponseWriter, request *http.Request) error
	CancelScanByID(w http.ResponseWriter, r *http.Request) error
}

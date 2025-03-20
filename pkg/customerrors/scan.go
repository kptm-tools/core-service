package customerrors

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var ErrScanNotFound = errors.New("scan not found")
var ErrScanHostFKNotFound = errors.New("insert or update on table scans violates foreign key constraint scans_host_id_fkey")

type ScanAlreadyFinishedError struct {
	ScanID uuid.UUID
	Status string
}

func NewScanAlreadyFinishedError(scanID uuid.UUID, currentStatus string) *ScanAlreadyFinishedError {
	return &ScanAlreadyFinishedError{
		ScanID: scanID,
		Status: currentStatus,
	}
}

func (e *ScanAlreadyFinishedError) Error() string {
	return fmt.Sprintf("scan %s has already finished with status %s", e.ScanID.String(), e.Status)
}

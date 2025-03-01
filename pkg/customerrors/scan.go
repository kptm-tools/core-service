package customerrors

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var ErrScanNotFound = errors.New("scan not found")

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

package interfaces

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IScanScheduleService interface {
	InsertScanScheduling(scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) error
	DeleteScanScheduleByID(int) (bool, error)
	PatchScanSchedule(scanScheduleID int, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID, operatorID, hostID uuid.UUID) error
	GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error)
	GetCurrentHostID(scanScheduleID int) (uuid.UUID, error)
}

type IScanScheduleHandlers interface {
	DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error
	PatchScanSchedule(w http.ResponseWriter, r *http.Request) error
	GetScanSchedules(w http.ResponseWriter, r *http.Request) error
}

package interfaces

import (
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"net/http"
	"time"
)

type IScanScheduleService interface {
	InsertScanScheduling(scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) error
	DeleteScanScheduleByID(int) (bool, error)
	PatchScanSchedule(int, domain.RepeatSchedule, time.Time) error
	GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error)
}

type IScanScheduleHandlers interface {
	DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error
	PatchScanSchedule(w http.ResponseWriter, r *http.Request) error
	GetScanSchedules(w http.ResponseWriter, r *http.Request) error
}

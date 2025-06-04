package interfaces

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IScanScheduleService interface {
	CreateScanSchedule(ctx context.Context, scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) (*domain.ScanSchedule, error)
	DeleteScanScheduleByID(context.Context, int) (bool, error)
	PatchScanSchedule(ctx context.Context, scanScheduleID int, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID, operatorID, hostID uuid.UUID) error
	GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error)
	GetCurrentHostID(ctx context.Context, scanScheduleID int) (uuid.UUID, error)
	UpdateScanScheduleScanID(ctx context.Context, scanID uuid.UUID, scanScheduleID int) error
	ScanScheduleDisableJob(context.Context, int) error
}

type IScanScheduleHandlers interface {
	DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error
	PatchScanSchedule(w http.ResponseWriter, r *http.Request) error
	GetScanSchedules(w http.ResponseWriter, r *http.Request) error
}

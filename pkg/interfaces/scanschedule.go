package interfaces

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IScanScheduleService interface {
	CreateScanSchedule(ctx context.Context, scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule, hostID uuid.UUID) (*domain.ScanSchedule, error)
	DeleteScanScheduleByID(context.Context, int32) (bool, error)
	PatchScanSchedule(ctx context.Context, scanScheduleID int32, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID, operatorID, hostID uuid.UUID) error
	GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error)
	GetCurrentHostID(ctx context.Context, scanScheduleID int32) (uuid.UUID, error)
	UpdateScanScheduleScanID(ctx context.Context, scanID uuid.UUID, scanScheduleID int32) error
	ScanScheduleDisableJob(context.Context, int32) error
}

type IScanScheduleHandlers interface {
	DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error
	PatchScanSchedule(w http.ResponseWriter, r *http.Request) error
	GetScanSchedules(w http.ResponseWriter, r *http.Request) error
}

type ScanScheduleRepository interface {
	CreateScanSchedule(context.Context, domain.ScanSchedule) (*domain.ScanSchedule, error)
	GetScanScheduleByID(context.Context, int32) (*domain.ScanSchedule, error)
	GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error)
	UpdateScanScheduling(context.Context, uuid.UUID, int32) error
	DeleteScanScheduleByID(context.Context, int32) (bool, error)
	PatchScanScheduleByID(context.Context, int32, uuid.UUID, string, bool, string, int32, time.Time) error
	EnableJob(context.Context, string, bool, int32) error
	DisableJob(context.Context, int32, bool) error
}

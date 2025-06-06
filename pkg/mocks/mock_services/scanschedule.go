package mock_services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type MockScanScheduleService struct {
	MockCreateScanSchedule         func(ctx context.Context, scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) (*domain.ScanSchedule, error)
	MockDeleteScanScheduleByID     func(context.Context, int) (bool, error)
	MockPatchScanSchedule          func(ctx context.Context, scanScheduleID int, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID, operatorID, hostID uuid.UUID) error
	MockGetScanSchedulesByTenantID func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error)
	MockGetCurrentHostID           func(ctx context.Context, scanScheduleID int) (uuid.UUID, error)
	MockUpdateScanScheduleScanID   func(ctx context.Context, scanID uuid.UUID, scanScheduleID int) error
	MockScanScheduleDisableJob     func(context.Context, int) error
}

var _ interfaces.IScanScheduleService = (*MockScanScheduleService)(nil)

func (m *MockScanScheduleService) CreateScanSchedule(ctx context.Context, scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) (*domain.ScanSchedule, error) {
	if m.MockCreateScanSchedule != nil {
		return m.MockCreateScanSchedule(ctx, scanID, scheduleAt, frequency)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method CreateScanSchedule called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockScanScheduleService) DeleteScanScheduleByID(ctx context.Context, id int) (bool, error) {
	if m.MockDeleteScanScheduleByID != nil {
		return m.MockDeleteScanScheduleByID(ctx, id)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method DeleteScanScheduleByID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockScanScheduleService) PatchScanSchedule(ctx context.Context, scanScheduleID int, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID, operatorID, hostID uuid.UUID) error {
	if m.MockPatchScanSchedule != nil {
		return m.MockPatchScanSchedule(ctx, scanScheduleID, frequency, scheduleAt, tenantID, operatorID, hostID)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method PatchScanSchedule called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockScanScheduleService) GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error) {
	if m.MockGetScanSchedulesByTenantID != nil {
		return m.MockGetScanSchedulesByTenantID(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method GetScanSchedulesByTenantID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockScanScheduleService) GetCurrentHostID(ctx context.Context, scanScheduleID int) (uuid.UUID, error) {
	if m.MockGetCurrentHostID != nil {
		return m.MockGetCurrentHostID(ctx, scanScheduleID)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method GetCurrentHostID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockScanScheduleService) UpdateScanScheduleScanID(ctx context.Context, scanID uuid.UUID, scanScheduleID int) error {
	if m.MockUpdateScanScheduleScanID != nil {
		return m.MockUpdateScanScheduleScanID(ctx, scanID, scanScheduleID)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method UpdateScanScheduleScanID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockScanScheduleService) ScanScheduleDisableJob(ctx context.Context, scheduleID int) error {
	if m.MockScanScheduleDisableJob != nil {
		return m.MockScanScheduleDisableJob(ctx, scheduleID)
	}
	panic(fmt.Sprintf("MockScanScheduleService: method ScanScheduleDisableJob called but not implemented for test: %s", ctx.Value("test_name")))
}

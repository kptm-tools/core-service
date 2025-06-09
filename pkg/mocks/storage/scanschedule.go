package mockstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockScanScheduleRepo struct {
	MockCreateScanSchedule         func(context.Context, domain.ScanSchedule) (*domain.ScanSchedule, error)
	MockGetScanScheduleByID        func(context.Context, int32) (*domain.ScanSchedule, error)
	MockGetScanSchedulesByTenantID func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error)
	MockUpdateScanScheduling       func(context.Context, uuid.UUID, int32) error
	MockDeleteScanScheduleByID     func(context.Context, int32) (bool, error)
	MockPatchScanScheduleByID      func(context.Context, int32, uuid.UUID, string, bool, string, int32, time.Time) error
	MockEnableJob                  func(context.Context, string, bool, int32) error
	MockDisableJob                 func(context.Context, int32, bool) error
}

// Ensure MockScanScheduleRepo satisfies the ScanScheduleRepository interface at compile time.
var _ interfaces.ScanScheduleRepository = (*MockScanScheduleRepo)(nil)

func (m *MockScanScheduleRepo) CreateScanSchedule(ctx context.Context, schedule domain.ScanSchedule) (*domain.ScanSchedule, error) {
	if m.MockCreateScanSchedule != nil {
		return m.MockCreateScanSchedule(ctx, schedule)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method CreateScanSchedule called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) GetScanScheduleByID(ctx context.Context, id int32) (*domain.ScanSchedule, error) {
	if m.MockGetScanScheduleByID != nil {
		return m.MockGetScanScheduleByID(ctx, id)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method GetScanScheduleByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error) {
	if m.MockGetScanSchedulesByTenantID != nil {
		return m.MockGetScanSchedulesByTenantID(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method GetScanSchedulesByTenantID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) UpdateScanScheduling(ctx context.Context, scanID uuid.UUID, scheduleID int32) error {
	if m.MockUpdateScanScheduling != nil {
		return m.MockUpdateScanScheduling(ctx, scanID, scheduleID)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method UpdateScanScheduling called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) DeleteScanScheduleByID(ctx context.Context, id int32) (bool, error) {
	if m.MockDeleteScanScheduleByID != nil {
		return m.MockDeleteScanScheduleByID(ctx, id)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method DeleteScanScheduleByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) PatchScanScheduleByID(ctx context.Context, id int32, scanID uuid.UUID, cron string, isRepeated bool, periodName string, periodQuantity int32, scheduledDate time.Time) error {
	if m.MockPatchScanScheduleByID != nil {
		return m.MockPatchScanScheduleByID(ctx, id, scanID, cron, isRepeated, periodName, periodQuantity, scheduledDate)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method PatchScanScheduleByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) EnableJob(ctx context.Context, cron string, isRepeated bool, scheduleID int32) error {
	if m.MockEnableJob != nil {
		return m.MockEnableJob(ctx, cron, isRepeated, scheduleID)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method EnableJob called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanScheduleRepo) DisableJob(ctx context.Context, scheduleID int32, isRepeated bool) error {
	if m.MockDisableJob != nil {
		return m.MockDisableJob(ctx, scheduleID, isRepeated)
	}
	panic(fmt.Sprintf("MockScanScheduleRepo: method DisableJob called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

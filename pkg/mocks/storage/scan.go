package mockstorage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockScanRepo struct {
	MockCreateScan                 func(context.Context, domain.Scan) (*domain.Scan, error)
	MockGetScansForTenant          func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error)
	MockGetScanByID                func(context.Context, uuid.UUID) (*domain.Scan, error)
	MockGetScanAssetsByID          func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error)
	MockGetScanInsightsBaseData    func(ctx context.Context, scanID uuid.UUID) (domain.ScanInsightsBaseData, error)
	MockGetLatestScanByHostID      func(ctx context.Context, hostID uuid.UUID, fromDate *time.Time, toDate *time.Time) (*domain.Scan, error)
	MockGetOldestScanByHostID      func(ctx context.Context, hostID uuid.UUID, fromDate *time.Time, toDate *time.Time) (*domain.Scan, error)
	MockGetPreviousScan            func(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error)
	MockGetProtectionScore         func(ctx context.Context, scanID uuid.UUID) (float64, error)
	MockGetReportsByTenantID       func(context.Context, uuid.UUID) ([]domain.ReportItem, error)
	MockUpdateProtectionScore      func(ctx context.Context, scanID uuid.UUID, newScore float64) error
	MockUpdateScanStatus           func(ctx context.Context, scanID uuid.UUID, newStatus enums.ScanStatus) error
	MockUpdateScanStatusAndEndedAt func(ctx context.Context, scanID uuid.UUID, newStatus enums.ScanStatus, endedAt time.Time) error
}

var _ interfaces.ScanRepository = (*MockScanRepo)(nil)

func (m *MockScanRepo) CreateScan(ctx context.Context, scan domain.Scan) (*domain.Scan, error) {
	if m.MockCreateScan != nil {
		return m.MockCreateScan(ctx, scan)
	}
	panic(fmt.Sprintf("MockScanRepo: method CreateScan called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetScansForTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error) {
	if m.MockGetScansForTenant != nil {
		return m.MockGetScansForTenant(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetScansForTenant called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetScanByID(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
	if m.MockGetScanByID != nil {
		return m.MockGetScanByID(ctx, id)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetScanByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetScanAssetsByID(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error) {
	if m.MockGetScanAssetsByID != nil {
		return m.MockGetScanAssetsByID(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetScanAssetsByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetScanInsightsBaseData(ctx context.Context, scanID uuid.UUID) (domain.ScanInsightsBaseData, error) {
	if m.MockGetScanInsightsBaseData != nil {
		return m.MockGetScanInsightsBaseData(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetScanInsightsBaseData called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetLatestScanByHostID(ctx context.Context, hostID uuid.UUID, fromDate *time.Time, toDate *time.Time) (*domain.Scan, error) {
	if m.MockGetLatestScanByHostID != nil {
		return m.MockGetLatestScanByHostID(ctx, hostID, fromDate, toDate)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetLatestScanByHostID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetOldestScanByHostID(ctx context.Context, hostID uuid.UUID, fromDate *time.Time, toDate *time.Time) (*domain.Scan, error) {
	if m.MockGetOldestScanByHostID != nil {
		return m.MockGetOldestScanByHostID(ctx, hostID, fromDate, toDate)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetOldestScanByHostID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetPreviousScan(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
	if m.MockGetPreviousScan != nil {
		return m.MockGetPreviousScan(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetPreviousScan called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error) {
	if m.MockGetProtectionScore != nil {
		return m.MockGetProtectionScore(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetProtectionScore called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) GetReportsByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ReportItem, error) {
	if m.MockGetReportsByTenantID != nil {
		return m.MockGetReportsByTenantID(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockScanRepo: method GetReportsByTenantID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) UpdateProtectionScore(ctx context.Context, scanID uuid.UUID, newScore float64) error {
	if m.MockUpdateProtectionScore != nil {
		return m.MockUpdateProtectionScore(ctx, scanID, newScore)
	}
	panic(fmt.Sprintf("MockScanRepo: method UpdateProtectionScore called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, newStatus enums.ScanStatus) error {
	if m.MockUpdateScanStatus != nil {
		return m.MockUpdateScanStatus(ctx, scanID, newStatus)
	}
	panic(fmt.Sprintf("MockScanRepo: method UpdateScanStatus called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanRepo) UpdateScanStatusAndEndedAt(ctx context.Context, scanID uuid.UUID, newStatus enums.ScanStatus, endedAt time.Time) error {
	if m.MockUpdateScanStatusAndEndedAt != nil {
		return m.MockUpdateScanStatusAndEndedAt(ctx, scanID, newStatus, endedAt)
	}
	panic(fmt.Sprintf("MockScanRepo: method UpdateScanStatusAndEndedAt called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

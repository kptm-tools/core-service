package mockservices

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockScanService struct {
	MockCreateScan                                 func(ctx context.Context, hostID uuid.UUID, tenantID, operatorID uuid.UUID, startedAt *time.Time) (*domain.Scan, error)
	MockGetCurrentScans                            func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error)
	MockInsertScanResult                           func(context.Context, domain.ScanResult) error
	MockUpdateScanStatus                           func(ctx context.Context, scanID uuid.UUID, status enums.ScanStatus) error
	MockMarkScanAsFailed                           func(ctx context.Context, scanID uuid.UUID) error
	MockMarkScanAsCancelled                        func(ctx context.Context, scanID uuid.UUID) error
	MockGetScanInsights                            func(ctx context.Context, scanID uuid.UUID) (*domain.ScanInsights, error)
	MockCalculateProtectionScore                   func(ctx context.Context, scanID uuid.UUID) (float64, error)
	MockGetScanByID                                func(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error)
	MockGetScanAssetsByID                          func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error)
	MockHandleScanCompletion                       func(ctx context.Context, scanID uuid.UUID) error
	MockGetScanVulnerabilitySummaryByID            func(ctx context.Context, scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	MockGetAllReportsForTenant                     func(context.Context, uuid.UUID) ([]domain.ReportItem, error)
	MockGetScoreCardTrendsForTenant                func(ctx context.Context, tenantID uuid.UUID, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error)
	MockGetScanVulnerabilities                     func(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error)
	MockGetSeverityCounts                          func(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	MockGetSeverityOSCountsByScanID                func(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	MockGetSeverityServiceCountsByScanID           func(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	MockGetSeverityServiceCountsByScanAndServiceID func(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error)
	MockCreateTarget                               func(ctx context.Context, hostID uuid.UUID) (*results.Target, error)
	MockGetScanRapporteursAndHostAlias             func(ctx context.Context, scanID uuid.UUID) ([]domain.Rapporteur, string, error)
	MockGetSeverityCountsFromToolVulns             func(ctx context.Context, vulns []tools.Vulnerability) tools.SeverityCounts
	MockGetSeverityCountsFromDomainVulnDetail      func(ctx context.Context, vulns []domain.ScanVulnerabilityDetail) tools.SeverityCounts
	MockGetInformationGatheredResults              func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error)
}

// Ensure MockScanService satisfies the IScanService interface at compile time.
var _ interfaces.IScanService = (*MockScanService)(nil)

func (m *MockScanService) CreateScan(ctx context.Context, hostID uuid.UUID, tenantID, operatorID uuid.UUID, startedAt *time.Time) (*domain.Scan, error) {
	if m.MockCreateScan != nil {
		return m.MockCreateScan(ctx, hostID, tenantID, operatorID, startedAt)
	}
	panic(fmt.Sprintf("MockScanService: method CreateScan called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetCurrentScans(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error) {
	if m.MockGetCurrentScans != nil {
		return m.MockGetCurrentScans(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockScanService: method GetCurrentScans called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) InsertScanResult(ctx context.Context, result domain.ScanResult) error {
	if m.MockInsertScanResult != nil {
		return m.MockInsertScanResult(ctx, result)
	}
	panic(fmt.Sprintf("MockScanService: method InsertScanResult called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status enums.ScanStatus) error {
	if m.MockUpdateScanStatus != nil {
		return m.MockUpdateScanStatus(ctx, scanID, status)
	}
	panic(fmt.Sprintf("MockScanService: method UpdateScanStatus called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) MarkScanAsFailed(ctx context.Context, scanID uuid.UUID) error {
	if m.MockMarkScanAsFailed != nil {
		return m.MockMarkScanAsFailed(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method MarkScanAsFailed called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) MarkScanAsCancelled(ctx context.Context, scanID uuid.UUID) error {
	if m.MockMarkScanAsCancelled != nil {
		return m.MockMarkScanAsCancelled(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method MarkScanAsCancelled called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScanInsights(ctx context.Context, scanID uuid.UUID) (*domain.ScanInsights, error) {
	if m.MockGetScanInsights != nil {
		return m.MockGetScanInsights(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetScanInsights called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) CalculateProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error) {
	if m.MockCalculateProtectionScore != nil {
		return m.MockCalculateProtectionScore(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method CalculateProtectionScore called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScanByID(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
	if m.MockGetScanByID != nil {
		return m.MockGetScanByID(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetScanByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScanAssetsByID(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error) {
	if m.MockGetScanAssetsByID != nil {
		return m.MockGetScanAssetsByID(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetScanAssetsByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) HandleScanCompletion(ctx context.Context, scanID uuid.UUID) error {
	if m.MockHandleScanCompletion != nil {
		return m.MockHandleScanCompletion(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method HandleScanCompletion called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScanVulnerabilitySummaryByID(ctx context.Context, scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error) {
	if m.MockGetScanVulnerabilitySummaryByID != nil {
		return m.MockGetScanVulnerabilitySummaryByID(ctx, scanID, timePeriodFilter, severityFilters)
	}
	panic(fmt.Sprintf("MockScanService: method GetScanVulnerabilitySummaryByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetAllReportsForTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.ReportItem, error) {
	if m.MockGetAllReportsForTenant != nil {
		return m.MockGetAllReportsForTenant(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockScanService: method GetAllReportsForTenant called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScoreCardTrendsForTenant(ctx context.Context, tenantID uuid.UUID, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error) {
	if m.MockGetScoreCardTrendsForTenant != nil {
		return m.MockGetScoreCardTrendsForTenant(ctx, tenantID, fromDate, toDate)
	}
	panic(fmt.Sprintf("MockScanService: method GetScoreCardTrendsForTenant called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScanVulnerabilities(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error) {
	if m.MockGetScanVulnerabilities != nil {
		return m.MockGetScanVulnerabilities(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetScanVulnerabilities called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetSeverityCounts(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	if m.MockGetSeverityCounts != nil {
		return m.MockGetSeverityCounts(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetSeverityCounts called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetSeverityOSCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	if m.MockGetSeverityOSCountsByScanID != nil {
		return m.MockGetSeverityOSCountsByScanID(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetSeverityOSCountsByScanID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetSeverityServiceCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	if m.MockGetSeverityServiceCountsByScanID != nil {
		return m.MockGetSeverityServiceCountsByScanID(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetSeverityServiceCountsByScanID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetSeverityServiceCountsByScanAndServiceID(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
	if m.MockGetSeverityServiceCountsByScanAndServiceID != nil {
		return m.MockGetSeverityServiceCountsByScanAndServiceID(ctx, scanID, serviceID)
	}
	panic(fmt.Sprintf("MockScanService: method GetSeverityServiceCountsByScanAndServiceID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) CreateTarget(ctx context.Context, hostID uuid.UUID) (*results.Target, error) {
	if m.MockCreateTarget != nil {
		return m.MockCreateTarget(ctx, hostID)
	}
	panic(fmt.Sprintf("MockScanService: method CreateTarget called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetScanRapporteursAndHostAlias(ctx context.Context, scanID uuid.UUID) ([]domain.Rapporteur, string, error) {
	if m.MockGetScanRapporteursAndHostAlias != nil {
		return m.MockGetScanRapporteursAndHostAlias(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetScanRapporteursAndHostAlias called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetSeverityCountsFromToolVulns(ctx context.Context, vulns []tools.Vulnerability) tools.SeverityCounts {
	if m.MockGetSeverityCountsFromToolVulns != nil {
		return m.MockGetSeverityCountsFromToolVulns(ctx, vulns)
	}
	panic(fmt.Sprintf("MockScanService: method GetSeverityCountsFromToolVulns called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetSeverityCountsFromDomainVulnDetail(ctx context.Context, vulns []domain.ScanVulnerabilityDetail) tools.SeverityCounts {
	if m.MockGetSeverityCountsFromDomainVulnDetail != nil {
		return m.MockGetSeverityCountsFromDomainVulnDetail(ctx, vulns)
	}
	panic(fmt.Sprintf("MockScanService: method GetSeverityCountsFromDomainVulnDetail called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanService) GetInformationGatheredResults(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
	if m.MockGetInformationGatheredResults != nil {
		return m.MockGetInformationGatheredResults(ctx, scanID)
	}
	panic(fmt.Sprintf("MockScanService: method GetInformationGatheredResults called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

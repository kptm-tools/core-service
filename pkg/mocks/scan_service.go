package mocks

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type MockScanService struct {
	MockCreateScan         func(hostID int, tenantID, operatorID string, startedAt *time.Time) (*domain.Scan, error)
	MockGetRapporteursScan func(id uuid.UUID) (*[]domain.Rapporteur, string)
}

func (m *MockScanService) CreateScan(hostID int, tenantID, operatorID string, startedAt *time.Time) (*domain.Scan, error) {
	if m.MockCreateScan != nil {
		return m.MockCreateScan(hostID, tenantID, operatorID, startedAt)
	}
	return nil, nil
}

func (m *MockScanService) GetRapporteursScan(id uuid.UUID) (*[]domain.Rapporteur, string) {
	if m.MockGetRapporteursScan != nil {
		return m.MockGetRapporteursScan(id)
	}
	return nil, ""
}

func (m *MockScanService) GetScans(s string) ([]*domain.ScanSummary, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) InsertScanResult(result *domain.ScanResult) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) InsertVulnerabilityResult(result *domain.ScanResult) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) UpdateScanStatus(scanID uuid.UUID, status enums.ScanStatus) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) MarkScanAsFailed(scanID uuid.UUID) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) MarkScanAsCancelled(scanID uuid.UUID) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetScanInsightsByID(scanID uuid.UUID) (*domain.ScanInsights, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) CalculateProtectionScore(scanID uuid.UUID) (float64, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetScanByID(scanID uuid.UUID) (*domain.Scan, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) HandleScanCompletion(scanID uuid.UUID) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetScanVulnerabilitySummaryByID(scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetAllReportsForTenant(tenantID string) ([]*domain.ReportItem, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetScoreCardTrendsForTenant(tenantID string, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetScanVulnerabilities(scanID uuid.UUID) ([]*domain.Vulnerability, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) GetSeverityCounts(scanID uuid.UUID) (*tools.SeverityCounts, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) CreateTarget(hostID int) (*results.Target, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) UpdateScanScheduleScanID(scanID uuid.UUID, scanScheduleID int) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockScanService) ScanScheduleDisableJob(i int) error {
	// TODO implement me
	panic("implement me")
}

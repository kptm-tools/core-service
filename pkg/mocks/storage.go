package mocks

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type MockStorage struct {
	MockCreateHost                         func(*domain.Host) (*domain.Host, error)
	MockGetHostsByTenantID                 func(string, []int) ([]*domain.Host, error)
	MockGetHostByID                        func(int) (*domain.Host, error)
	MockDeleteHostByID                     func(int) (bool, error)
	MockPatchHostByID                      func(*domain.Host) (*domain.Host, error)
	MockCreateTenant                       func(*domain.Tenant) (*domain.Tenant, error)
	MockGetTenants                         func() ([]*domain.Tenant, error)
	MockPing                               func() error
	MockCreateScan                         func(*domain.Scan) (*domain.Scan, error)
	MockExistAlias                         func(string) (bool, error)
	MockGetScans                           func(tenantID string) ([]*domain.ScanSummary, error)
	MockGetScanByID                        func(UUID uuid.UUID) (*domain.Scan, error)
	MockInsertScanResult                   func(*sql.Tx, *domain.ScanResult) error
	MockInsertVulnerabilityResult          func(*domain.ScanResult) error
	MockUpdateScanStatus                   func(scanID uuid.UUID, status string) error
	MockUpdateScanStatusAndEndedAt         func(tx *sql.Tx, scanID uuid.UUID, status string, endedAt time.Time) error
	MockGetScanInsights                    func(scanID uuid.UUID) (*domain.ScanInsights, error)
	MockGetProtectionScore                 func(scanID uuid.UUID) (float64, error)
	MockUpdateProtectionScore              func(scanID uuid.UUID, score float64) error
	MockGetWhoisResult                     func(scanID uuid.UUID) (*tools.WhoIsResult, error)
	MockGetDNSLookupResult                 func(scanID uuid.UUID) (*tools.DNSLookupResult, error)
	MockGetHarvesterResult                 func(scanID uuid.UUID) (*tools.HarvesterResult, error)
	MockGetNmapResult                      func(scanID uuid.UUID) (*tools.NmapResult, error)
	MockGetScanVulnerabilitiesSummary      func(scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	MockGetReportsByTenantID               func(tenantID string) ([]*domain.ReportItem, error)
	MockGetLatestScanByHostID              func(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error)
	MockGetScanBeforeLatestByHostID        func(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error)
	MockGetOldestScanByHostID              func(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error)
	MockGetScanVulnerabilities             func(uuid.UUID) ([]*domain.Vulnerability, error)
	MockGetScanVulnerabilityCount          func(uuid.UUID) (int, error)
	MockGetSeverityCounts                  func(uuid.UUID) (*tools.SeverityCounts, error)
	MockGetOSByID                          func(int) (*tools.OSData, error)
	MockGetServiceByID                     func(int) (*tools.PortData, error)
	MockGetVulnerabilityByID               func(int) (*domain.Vulnerability, error)
	MockCreateScanScheduling               func(scanID uuid.UUID, cronExpression string, isRepeated bool, periodName string, periodQuantity int, scheduledDate time.Time) error
	MockScanScheduleDisableJob             func(scanScheduleID int, withDelete bool) error
	MockUpdateScanScheduling               func(scanID uuid.UUID, scanScheduleID int) error
	MockDeleteScanScheduleByID             func(scanScheduleID int) (bool, error)
	MockGetScanSchedules                   func(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error)
	MockPatchScanScheduleByID              func(scanScheduleID int, scanID uuid.UUID, cronExpr string, isRepeated bool, periodName string, periodQuantity int, scheduleDate time.Time) error
	MockGetCurrentHostIDFromScanSchedule   func(scanScheduleID int) (int, error)
	MockScanScheduleEnableJob              func(cronExp string, hasPeriod bool, scanScheduleID int) error
	MockGetHostVulnerabilityTrends         func(hostID int, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) ([]domain.ServiceTimePeriod, error)
	MockGetRapporteursAndHostAliasByScanID func(scanID uuid.UUID) ([]*domain.Rapporteur, string, error)
	MockUpdateVulnerabilityComment         func(ID int, comment string) (bool, error)
	MockDeleteVulnerabilityComment         func(ID int) (bool, error)
	MockHasComment                         func(ID int) (bool, error)
}

func (m *MockStorage) CreateHost(arg0 *domain.Host) (*domain.Host, error) {
	if m.MockCreateHost != nil {
		return m.MockCreateHost(arg0)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetHostsByTenantID(arg0 string, arg1 []int) ([]*domain.Host, error) {
	if m.MockGetHostsByTenantID != nil {
		return m.MockGetHostsByTenantID(arg0, arg1)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetHostByID(arg0 int) (*domain.Host, error) {
	if m.MockGetHostByID != nil {
		return m.MockGetHostByID(arg0)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) DeleteHostByID(arg0 int) (bool, error) {
	if m.MockDeleteHostByID != nil {
		return m.MockDeleteHostByID(arg0)
	}
	return false, nil // Default behavior if mock function not set
}

func (m *MockStorage) PatchHostByID(arg0 *domain.Host) (*domain.Host, error) {
	if m.MockPatchHostByID != nil {
		return m.MockPatchHostByID(arg0)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) CreateTenant(arg0 *domain.Tenant) (*domain.Tenant, error) {
	if m.MockCreateTenant != nil {
		return m.MockCreateTenant(arg0)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetTenants() ([]*domain.Tenant, error) {
	if m.MockGetTenants != nil {
		return m.MockGetTenants()
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) Ping() error {
	if m.MockPing != nil {
		return m.MockPing()
	}
	return nil // Default behavior if mock function not set
}

func (m *MockStorage) CreateScan(arg0 *domain.Scan) (*domain.Scan, error) {
	if m.MockCreateScan != nil {
		return m.MockCreateScan(arg0)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) ExistAlias(arg0 string) (bool, error) {
	if m.MockExistAlias != nil {
		return m.MockExistAlias(arg0)
	}
	return false, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetScans(tenantID string) ([]*domain.ScanSummary, error) {
	if m.MockGetScans != nil {
		return m.MockGetScans(tenantID)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetScanByID(arg0 uuid.UUID) (*domain.Scan, error) {
	if m.MockGetScanByID != nil {
		return m.MockGetScanByID(arg0)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) InsertScanResult(arg0 *sql.Tx, arg1 *domain.ScanResult) error {
	if m.MockInsertScanResult != nil {
		return m.MockInsertScanResult(arg0, arg1)
	}
	return nil // Default behavior if mock function not set
}

func (m *MockStorage) InsertVulnerabilityResult(arg0 *domain.ScanResult) error {
	if m.MockInsertVulnerabilityResult != nil {
		return m.MockInsertVulnerabilityResult(arg0)
	}
	return nil // Default behavior if mock function not set
}

func (m *MockStorage) UpdateScanStatus(scanID uuid.UUID, status string) error {
	if m.MockUpdateScanStatus != nil {
		return m.MockUpdateScanStatus(scanID, status)
	}
	return nil // Default behavior if mock function not set
}

func (m *MockStorage) UpdateScanStatusAndEndedAt(tx *sql.Tx, scanID uuid.UUID, status string, endedAt time.Time) error {
	if m.MockUpdateScanStatusAndEndedAt != nil {
		return m.MockUpdateScanStatusAndEndedAt(tx, scanID, status, endedAt)
	}
	return nil // Default behavior if mock function not set
}

func (m *MockStorage) GetScanInsights(scanID uuid.UUID) (*domain.ScanInsights, error) {
	if m.MockGetScanInsights != nil {
		return m.MockGetScanInsights(scanID)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetProtectionScore(scanID uuid.UUID) (float64, error) {
	if m.MockGetProtectionScore != nil {
		return m.MockGetProtectionScore(scanID)
	}
	return 0, nil // Default behavior if mock function not set
}

func (m *MockStorage) UpdateProtectionScore(scanID uuid.UUID, score float64) error {
	if m.MockUpdateProtectionScore != nil {
		return m.MockUpdateProtectionScore(scanID, score)
	}
	return nil // Default behavior if mock function not set
}

func (m *MockStorage) GetWhoisResult(scanID uuid.UUID) (*tools.WhoIsResult, error) {
	if m.MockGetWhoisResult != nil {
		return m.MockGetWhoisResult(scanID)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetDNSLookupResult(scanID uuid.UUID) (*tools.DNSLookupResult, error) {
	if m.MockGetDNSLookupResult != nil {
		return m.MockGetDNSLookupResult(scanID)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetHarvesterResult(scanID uuid.UUID) (*tools.HarvesterResult, error) {
	if m.MockGetHarvesterResult != nil {
		return m.MockGetHarvesterResult(scanID)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetNmapResult(scanID uuid.UUID) (*tools.NmapResult, error) {
	if m.MockGetNmapResult != nil {
		return m.MockGetNmapResult(scanID)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetScanVulnerabilitiesSummary(scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error) {
	if m.MockGetScanVulnerabilitiesSummary != nil {
		return m.MockGetScanVulnerabilitiesSummary(scanID, timePeriodFilter, severityFilters)
	}
	return nil, nil // Default behavior if mock function not set
}

func (m *MockStorage) GetReportsByTenantID(tenantID string) ([]*domain.ReportItem, error) {
	if m.MockGetReportsByTenantID != nil {
		return m.MockGetReportsByTenantID(tenantID)
	}
	return nil, nil // Default behaviour if mock function is not set
}

func (m *MockStorage) GetLatestScanByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error) {
	if m.MockGetLatestScanByHostID != nil {
		return m.MockGetLatestScanByHostID(hostID, fromDate, toDate)
	}
	return nil, nil
}

func (m *MockStorage) GetScanBeforeLatestByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error) {
	if m.MockGetScanBeforeLatestByHostID != nil {
		return m.MockGetScanBeforeLatestByHostID(hostID, fromDate, toDate)
	}
	return nil, nil
}

func (m *MockStorage) GetOldestScanByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error) {
	if m.MockGetOldestScanByHostID != nil {
		return m.MockGetOldestScanByHostID(hostID, fromDate, toDate)
	}
	return nil, nil
}

func (m *MockStorage) GetScanVulnerabilities(scanID uuid.UUID) ([]*domain.Vulnerability, error) {
	if m.MockGetScanVulnerabilities != nil {
		return m.MockGetScanVulnerabilities(scanID)
	}
	return nil, nil
}

func (m *MockStorage) GetScanVulnerabilityCount(scanID uuid.UUID) (int, error) {
	if m.MockGetScanVulnerabilityCount != nil {
		return m.MockGetScanVulnerabilityCount(scanID)
	}
	return 0, nil
}

func (m *MockStorage) GetSeverityCounts(scanID uuid.UUID) (*tools.SeverityCounts, error) {
	if m.MockGetSeverityCounts != nil {
		return m.MockGetSeverityCounts(scanID)
	}
	return nil, nil
}

func (m *MockStorage) GetOSByID(operatingSystemID int) (*tools.OSData, error) {
	if m.MockGetOSByID != nil {
		return m.MockGetOSByID(operatingSystemID)
	}
	return nil, nil
}

func (m *MockStorage) GetServiceByID(serviceID int) (*tools.PortData, error) {
	if m.MockGetServiceByID != nil {
		return m.MockGetServiceByID(serviceID)
	}
	return nil, nil
}

func (m *MockStorage) GetVulnerabilityByID(vulnID int) (*domain.Vulnerability, error) {
	if m.MockGetVulnerabilityByID != nil {
		return m.MockGetVulnerabilityByID(vulnID)
	}
	return nil, nil
}

func (m *MockStorage) CreateScanScheduling(scanID uuid.UUID, cronExpression string, isRepeated bool, periodName string, periodQuantity int, scheduledDate time.Time) error {
	if m.MockCreateScanScheduling != nil {
		return m.MockCreateScanScheduling(scanID, cronExpression, isRepeated, periodName, periodQuantity, scheduledDate)
	}
	return nil
}

func (m *MockStorage) ScanScheduleDisableJob(scanScheduleID int, withDelete bool) error {
	if m.MockScanScheduleDisableJob != nil {
		return m.MockScanScheduleDisableJob(scanScheduleID, withDelete)
	}
	return nil
}

func (m *MockStorage) UpdateScanScheduling(scanID uuid.UUID, scanScheduleID int) error {
	if m.MockUpdateScanScheduling != nil {
		return m.MockUpdateScanScheduling(scanID, scanScheduleID)
	}
	return nil
}

func (m *MockStorage) DeleteScanScheduleByID(scanScheduleID int) (bool, error) {
	if m.MockDeleteScanScheduleByID != nil {
		return m.MockDeleteScanScheduleByID(scanScheduleID)
	}
	return true, nil
}

func (m *MockStorage) GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
	if m.MockGetScanSchedules != nil {
		return m.MockGetScanSchedules(tenantID)
	}
	return nil, nil
}

func (m *MockStorage) PatchScanScheduleByID(scanScheduleID int, scanID uuid.UUID, cronExpr string, isRepeated bool, periodName string, periodQuantity int, scheduleDate time.Time) error {
	if m.MockPatchScanScheduleByID != nil {
		return m.MockPatchScanScheduleByID(scanScheduleID, scanID, cronExpr, isRepeated, periodName, periodQuantity, scheduleDate)
	}
	return nil
}

func (m *MockStorage) GetCurrentHostIDFromScanSchedule(scanScheduleID int) (int, error) {
	if m.MockGetCurrentHostIDFromScanSchedule != nil {
		return m.MockGetCurrentHostIDFromScanSchedule(scanScheduleID)
	}
	return -1, nil
}

func (m *MockStorage) ScanScheduleEnableJob(cronExp string, hasPeriod bool, scanScheduleID int) error {
	if m.MockScanScheduleEnableJob != nil {
		return m.MockScanScheduleEnableJob(cronExp, hasPeriod, scanScheduleID)
	}
	return nil
}

func (m *MockStorage) GetHostVulnerabilityTrends(hostID int, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) ([]domain.ServiceTimePeriod, error) {
	if m.MockGetHostVulnerabilityTrends != nil {
		return m.MockGetHostVulnerabilityTrends(hostID, timePeriodFilter, severityFilters)
	}
	return nil, nil
}

func (m *MockStorage) GetRapporteursAndHostAliasByScanID(scanID uuid.UUID) ([]*domain.Rapporteur, string, error) {
	if m.MockGetRapporteursAndHostAliasByScanID != nil {
		return m.GetRapporteursAndHostAliasByScanID(scanID)
	}
	return nil, "", nil
}

func (m *MockStorage) UpdateVulnerabilityComment(ID int, comment string) (bool, error) {
	if m.MockUpdateVulnerabilityComment != nil {
		return m.MockUpdateVulnerabilityComment(ID, comment)
	}
	return true, nil
}
func (m *MockStorage) DeleteVulnerabilityComment(ID int) (bool, error) {
	if m.MockDeleteVulnerabilityComment != nil {
		return m.MockDeleteVulnerabilityComment(ID)
	}
	return true, nil
}
func (m *MockStorage) HasComment(ID int) (bool, error) {
	if m.MockHasComment != nil {
		return m.MockHasComment(ID)
	}
	return true, nil
}

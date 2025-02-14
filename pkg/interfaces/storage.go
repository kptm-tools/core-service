package interfaces

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IStorage interface {
	CreateHost(*domain.Host) (*domain.Host, error)
	GetHostsByTenantID(string) ([]*domain.Host, error)
	GetHostByID(int) (*domain.Host, error)
	DeleteHostByID(int) (bool, error)
	PatchHostByID(*domain.Host) (*domain.Host, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	Ping() error
	CreateScan(*domain.Scan) (*domain.Scan, error)
	ExistAlias(string) (bool, error)
	GetScans(tenantID string) ([]*domain.ScanSummary, error)
	GetScanByID(UUID uuid.UUID) (*domain.Scan, error)
	InsertScanResult(*sql.Tx, *domain.ScanResult) error
	InsertVulnerabilityResult(*domain.ScanResult) error
	UpdateScanStatus(scanID uuid.UUID, status string) error
	UpdateScanStatusAndEndedAt(tx *sql.Tx, scanID uuid.UUID, status string, endedAt time.Time) error
	GetScanInsights(scanID uuid.UUID) (*domain.ScanInsights, error)
	GetProtectionScore(scanID uuid.UUID) (float64, error)
	UpdateProtectionScore(scanID uuid.UUID, score float64) error
	GetWhoisResult(scanID uuid.UUID) (*tools.WhoIsResult, error)
	GetDNSLookupResult(scanID uuid.UUID) (*tools.DNSLookupResult, error)
	GetHarvesterResult(scanID uuid.UUID) (*tools.HarvesterResult, error)
	GetNmapResult(scanID uuid.UUID) (*tools.NmapResult, error)
	GetScanVulnerabilitiesSummary(scanID uuid.UUID, timePeriodFilter string, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	GetReportsByTenantID(string) ([]*domain.ReportItem, error)
	GetLatestScanByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error)
	GetOldestScanByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error)
	GetScanVulnerabilities(uuid.UUID) ([]*domain.Vulnerability, error)
	GetSeverityCounts(uuid.UUID) (*tools.SeverityCounts, error)
	GetVulnerabilityByID(int) (*domain.Vulnerability, error)
	GetOSByID(int) (*tools.OSData, error)
	GetServiceByID(int) (*tools.PortData, error)
	CreateScanScheduling(uuid.UUID, string, bool) error
	ScanScheduleDisableJob(int) error
	UpdateScanScheduling(uuid.UUID, int) error
}

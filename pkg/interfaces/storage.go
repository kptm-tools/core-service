package interfaces

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type IStorage interface {
	CreateHost(context.Context, *domain.Host) (*domain.Host, error)
	GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID, hostsIDFilter []uuid.UUID) ([]*domain.Host, error)
	GetHostByID(context.Context, uuid.UUID) (*domain.Host, error)
	DeleteHostByID(uuid.UUID) (bool, error)
	PatchHostByID(context.Context, *domain.Host) (*domain.Host, error)
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	Ping() error
	CreateScan(*domain.Scan) (*domain.Scan, error)
	ExistAlias(string) (bool, error)
	GetCurrentScans(tenantID string) ([]*domain.ScanSummary, error)
	GetScanByID(UUID uuid.UUID) (*domain.Scan, error)
	InsertScanResult(*sql.Tx, *domain.ScanResult) error
	InsertVulnerabilityResult(context.Context, *domain.ScanResult) error
	UpdateScanStatus(scanID uuid.UUID, status string) error
	UpdateScanStatusAndEndedAt(tx *sql.Tx, scanID uuid.UUID, status string, endedAt time.Time) error
	GetScanInsights(scanID uuid.UUID) (*domain.ScanInsights, error)
	GetProtectionScore(scanID uuid.UUID) (float64, error)
	UpdateProtectionScore(scanID uuid.UUID, score float64) error
	GetWhoisResult(scanID uuid.UUID) (*tools.WhoIsResult, error)
	GetDNSLookupResult(scanID uuid.UUID) (*tools.DNSLookupResult, error)
	GetHarvesterResult(scanID uuid.UUID) (*tools.HarvesterResult, error)
	GetNmapResult(scanID uuid.UUID) (*tools.NmapResult, error)
	GetScanVulnerabilitiesSummary(scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	GetReportsByTenantID(string) ([]*domain.ReportItem, error)
	GetLatestScanByHostID(hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error)
	GetScanBeforeLatestByHostID(hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error)
	GetOldestScanByHostID(hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error)
	GetScanVulnerabilities(uuid.UUID) ([]*domain.Vulnerability, error)
	GetScanVulnerabilityCount(uuid.UUID) (int, error)
	GetSeverityCounts(uuid.UUID) (*tools.SeverityCounts, error)
	GetVulnerabilityByID(int) (*domain.Vulnerability, error)
	CreateScanScheduling(uuid.UUID, string, bool, string, int, time.Time) error
	ScanScheduleDisableJob(int, bool) error
	UpdateScanScheduling(uuid.UUID, int) error
	DeleteScanScheduleByID(int) (bool, error)
	GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error)
	PatchScanScheduleByID(int, uuid.UUID, string, bool, string, int, time.Time) error
	GetCurrentHostIDFromScanSchedule(int) (uuid.UUID, error)
	ScanScheduleEnableJob(string, bool, int) error
	GetHostVulnerabilityTrends(hostID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) ([]domain.ServiceTimePeriod, error)
	GetRapporteursAndHostAliasByScanID(scanID uuid.UUID) ([]*domain.Rapporteur, string, error)
	UpdateVulnerabilityComment(ID int, comment string) (bool, error)
	DeleteVulnerabilityComment(ID int) (bool, error)
	HasComment(ID int) (bool, error)
}

type HostRepository interface {
	CreateHost(ctx context.Context, host *domain.Host) (*domain.Host, error)
	GetHostByID(context.Context, uuid.UUID) (*domain.Host, error)
	GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID, hostsIDFilter []uuid.UUID) ([]*domain.Host, error)
	DeleteHostByID(context.Context, uuid.UUID) (bool, error)
	PatchHostByID(context.Context, domain.Host) (*domain.Host, error)
}

type ScanRepository interface {
	GetScanByID(context.Context, uuid.UUID) (*domain.Scan, error)
}

type ScanResultRepository interface {
	InsertVulnerabilityResult(context.Context, *domain.ScanResult) error
}

type VulnerabilityRepository interface {
	CreateVulnerability(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, vuln tools.Vulnerability, vulnType repository.VulnerabilityTypeEnum) (*tools.Vulnerability, error)
	GetVulnerabilityByID(context.Context, uuid.UUID) (*tools.Vulnerability, error)
	UpdateVulnerabilityComment(context.Context, uuid.UUID, string) (bool, error)
	GetVulnerabilitiesWithCveDetailByScanID(context.Context, uuid.UUID) ([]tools.Vulnerability, error)
	GetNetworkOSVulnerability(ctx context.Context, vulnID uuid.UUID) (*domain.NetworkOSVulnerability, error)
	GetVulnerabilityType(ctx context.Context, vulnID uuid.UUID) (repository.VulnerabilityTypeEnum, error)
	DeleteVulnerabilityComment(context.Context, uuid.UUID) (bool, error)
	HasComment(context.Context, uuid.UUID) (bool, error)
	GetSeverityCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
}

type OSRepository interface {
	CreateOS(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, osData tools.OSData) (*domain.OperatingSystem, error)
	GetOSByID(ctx context.Context, osID int32) (*domain.OperatingSystem, error)
}

type ServiceRepository interface {
	CreateOrUpdateService(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, portData tools.PortData) (*domain.Service, error)
	GetServiceByID(context.Context, int32) (*domain.Service, error)
}

type CVERepository interface {
	CreateOrUpdateCVE(ctx context.Context, vuln tools.Vulnerability) (*repository.CveDetail, error)
}

// TxFunc is a function that takes a context with an active transaction
// and can perform database operations
type TxFunc func(ctx context.Context) error

// TxManager provides methods for executing functions within a database transaction.
type TxManager interface {
	DoInTX(ctx context.Context, fn TxFunc) error
	// GetDB returns the underlying *sql.DB for non-transactional operations
	// or for starting explicit transactions in complex scenarios if needed.
	GetDB() *sql.DB
}

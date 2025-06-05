package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type IStorage interface {
	Ping() error
}

type HostRepository interface {
	CreateHost(ctx context.Context, host *domain.Host) (*domain.Host, error)
	GetHostByID(context.Context, uuid.UUID) (*domain.Host, error)
	GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID, hostsIDFilter []uuid.UUID) ([]*domain.Host, error)
	DeleteHostByID(context.Context, uuid.UUID) (bool, error)
	PatchHostByID(context.Context, domain.Host) (*domain.Host, error)
	AliasExists(context.Context, string) (bool, error)
}

type ScanRepository interface {
	CreateScan(context.Context, domain.Scan) (*domain.Scan, error)
	GetScansForTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error)
	GetScanByID(context.Context, uuid.UUID) (*domain.Scan, error)
	GetScanInsightsBaseData(ctx context.Context, scanID uuid.UUID) (domain.ScanInsightsBaseData, error)
	GetLatestScanByHostID(ctx context.Context, hostID uuid.UUID, fromDate *time.Time, toDate *time.Time) (*domain.Scan, error)
	GetOldestScanByHostID(ctx context.Context, hostID uuid.UUID, fromDate *time.Time, toDate *time.Time) (*domain.Scan, error)
	GetPreviousScan(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error)
	GetProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error)
	GetReportsByTenantID(context.Context, uuid.UUID) ([]domain.ReportItem, error)
	UpdateProtectionScore(ctx context.Context, scanID uuid.UUID, newScore float64) error
	UpdateScanStatus(ctx context.Context, scanID uuid.UUID, newStatus enums.ScanStatus) error
	UpdateScanStatusAndEndedAt(ctx context.Context, scanID uuid.UUID, newStatus enums.ScanStatus, endedAt time.Time) error
}

type ScanScheduleRepository interface {
	CreateScanSchedule(context.Context, domain.ScanSchedule) (*domain.ScanSchedule, error)
	GetScanScheduleByID(context.Context, int) (*domain.ScanSchedule, error)
	GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error)
	UpdateScanScheduling(context.Context, uuid.UUID, int) error
	DeleteScanScheduleByID(context.Context, int) (bool, error)
	PatchScanScheduleByID(context.Context, int, uuid.UUID, string, bool, string, int, time.Time) error
	EnableJob(context.Context, string, bool, int) error
	DisableJob(context.Context, int, bool) error
}

type ScanResultRepository interface {
	CreateScanResult(context.Context, domain.ScanResult) error
}

type VulnerabilityRepository interface {
	CreateVulnerability(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, vuln tools.Vulnerability, vulnType repository.VulnerabilityTypeEnum) (*tools.Vulnerability, error)
	GetVulnerabilityByID(context.Context, uuid.UUID) (*tools.Vulnerability, error)
	UpdateVulnerabilityComment(context.Context, uuid.UUID, string) (bool, error)
	GetVulnerabilitiesWithCveDetailByScanID(context.Context, uuid.UUID) ([]tools.Vulnerability, error)
	CreateNetworkOSVulnerabilityForOS(ctx context.Context, vulnID, scanID, hostID uuid.UUID, osID int32) error
	CreateNetworkOSVulnerabilityForService(ctx context.Context, vulnID, scanID, hostID uuid.UUID, serviceID int32) error
	GetNetworkOSVulnerability(ctx context.Context, vulnID uuid.UUID) (*domain.NetworkOSVulnerability, error)
	GetVulnerabilityType(ctx context.Context, vulnID uuid.UUID) (repository.VulnerabilityTypeEnum, error)
	DeleteVulnerabilityComment(context.Context, uuid.UUID) (bool, error)
	HasComment(context.Context, uuid.UUID) (bool, error)
	GetSeverityCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	GetScanVulnerabilityAggregates(context.Context, domain.VulnerabilityAggregatesParams) (*domain.VulnerabilityAggregatesResult, error)
	GetVulnerabilityCountByScanID(ctx context.Context, scanID uuid.UUID) (int, error)
	GetVulnerabilityCategoriesByScan(context.Context, domain.VulnerabilityCategoriesParams) ([]domain.ServiceCategoryData, error)
	GetHostVulnerabilityTrends(context.Context, domain.VulnerabilityTrendsParams) ([]domain.ServiceTimePeriod, error)
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
}

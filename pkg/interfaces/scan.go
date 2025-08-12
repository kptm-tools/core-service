package interfaces

import (
	"context"
	"net/http"
	"time"

	"github.com/kptm-tools/common/common/pkg/results"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IScanService interface {
	CreateScan(ctx context.Context, hostID uuid.UUID, tenantID, operatorID uuid.UUID, startedAt *time.Time) (*domain.Scan, error)
	GetCurrentScans(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error)
	InsertScanResult(context.Context, domain.ScanResult) error
	UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status enums.ScanStatus) error
	MarkScanAsFailed(ctx context.Context, scanID uuid.UUID) error
	MarkScanAsCancelled(ctx context.Context, scanID uuid.UUID) error
	GetScanInsights(ctx context.Context, scanID uuid.UUID) (*domain.ScanInsights, error)
	CalculateProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error)
	GetScanByID(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error)
	GetScanAssetsByID(context.Context, uuid.UUID) ([]domain.ScanOSandServicesResult, error)
	HandleScanCompletion(ctx context.Context, scanID uuid.UUID) error
	GetScanVulnerabilitySummaryByID(ctx context.Context, scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	GetAllReportsForTenant(context.Context, uuid.UUID) ([]domain.ReportItem, error)
	GetScoreCardTrendsForTenant(ctx context.Context, tenantID uuid.UUID, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error)
	GetScanVulnerabilities(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error)
	GetSeverityCounts(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	GetSeverityOSCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	GetSeverityServiceCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	GetSeverityServiceCountsByScanAndServiceID(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error)
	CreateTarget(ctx context.Context, hostID uuid.UUID) (*results.Target, error)
	GetScanRapporteursAndHostAlias(ctx context.Context, scanID uuid.UUID) ([]domain.Rapporteur, string, error)
	GetSeverityCountsFromToolVulns(ctx context.Context, vulns []tools.Vulnerability) tools.SeverityCounts
	GetSeverityCountsFromDomainVulnDetail(ctx context.Context, vulns []domain.ScanVulnerabilityDetail) tools.SeverityCounts
	GetInformationGatheredResults(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error)
}

type IScanHandlers interface {
	CreateScan(writer http.ResponseWriter, request *http.Request) error
	GetScanAssetsByID(writer http.ResponseWriter, request *http.Request) error
	CancelScanByID(w http.ResponseWriter, r *http.Request) error
	GetScanInsightsByID(w http.ResponseWriter, r *http.Request) error
	GetScanVulnerabilitySummaryByID(w http.ResponseWriter, r *http.Request) error
	GetScanOperatingSystemVulnerabilitiesByID(w http.ResponseWriter, r *http.Request) error
	GetScanServicesVulnerabilitiesByServiceID(w http.ResponseWriter, r *http.Request) error
	GetReports(w http.ResponseWriter, r *http.Request) error
	GetScoreCardTrends(w http.ResponseWriter, r *http.Request) error
	GetScanVulnerabilities(w http.ResponseWriter, r *http.Request) error
	DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error
	GetScanResultsByScanID(w http.ResponseWriter, r *http.Request) error
}

type ScanRepository interface {
	CreateScan(context.Context, domain.Scan) (*domain.Scan, error)
	GetScansForTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error)
	GetScanByID(context.Context, uuid.UUID) (*domain.Scan, error)
	GetScanAssetsByID(context.Context, uuid.UUID) ([]domain.ScanOSandServicesResult, error)
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

type ScanResultRepository interface {
	CreateScanResult(context.Context, domain.ScanResult) error
	GetScanResultsByScanID(ctx context.Context, scanID uuid.UUID, tools []string) ([]domain.ScanResult, error)
}

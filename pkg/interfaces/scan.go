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
	InsertVulnerabilityResult(context.Context, *domain.ScanResult) error
	UpdateScanStatus(scanID uuid.UUID, status enums.ScanStatus) error
	MarkScanAsFailed(ctx context.Context, scanID uuid.UUID) error
	MarkScanAsCancelled(ctx context.Context, scanID uuid.UUID) error
	GetScanInsights(ctx context.Context, scanID uuid.UUID) (*domain.ScanInsights, error)
	CalculateProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error)
	GetScanByID(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error)
	HandleScanCompletion(scanID uuid.UUID) error
	GetScanVulnerabilitySummaryByID(scanID uuid.UUID, timePeriodFilter domain.TimePeriodFilter, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	GetAllReportsForTenant(tenantID string) ([]*domain.ReportItem, error)
	GetScoreCardTrendsForTenant(ctx context.Context, tenantID uuid.UUID, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error)
	GetScanVulnerabilities(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error)
	GetSeverityCounts(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error)
	CreateTarget(ctx context.Context, hostID uuid.UUID) (*results.Target, error)
	GetScanRapporteursAndHostAlias(ctx context.Context, scanID uuid.UUID) ([]domain.Rapporteur, string, error)
}

type IScanHandlers interface {
	CreateScan(writer http.ResponseWriter, request *http.Request) error
	CancelScanByID(w http.ResponseWriter, r *http.Request) error
	GetScanInsightsByID(w http.ResponseWriter, r *http.Request) error
	GetScanVulnerabilitySummaryByID(w http.ResponseWriter, r *http.Request) error
	GetReports(w http.ResponseWriter, r *http.Request) error
	GetScoreCardTrends(w http.ResponseWriter, r *http.Request) error
	GetScanVulnerabilities(w http.ResponseWriter, r *http.Request) error
	DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error
}

package interfaces

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IScanService interface {
	CreateScans(hostIDs []int, tenantID, operatorID string) ([]*domain.Scan, error)
	GetScans(string) ([]*domain.ScanSummary, error)
	InsertScanResult(*domain.ScanResult) error
	InsertVulnerabilityResult(*domain.ScanResult) error
	UpdateScanStatus(scanID uuid.UUID, status enums.ScanStatus) error
	MarkScanAsFailed(scanID uuid.UUID) error
	MarkScanAsCancelled(scanID uuid.UUID) error
	GetScanInsightsByID(scanID uuid.UUID) (*domain.ScanInsights, error)
	CalculateProtectionScore(scanID uuid.UUID) (float64, error)
	GetScanByID(scanID uuid.UUID) (*domain.Scan, error)
	HandleScanCompletion(scanID uuid.UUID) error
	GetScanVulnerabilitySummaryByID(scanID uuid.UUID, timePeriodFilter string, severityFilters []string) (*domain.ScanVulnerabilitySummaryData, error)
	GetAllReportsForTenant(tenantID string) ([]*domain.ReportItem, error)
	GetScoreCardTrendsForTenant(tenantID string, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error)
}

type IScanHandlers interface {
	CreateScans(writer http.ResponseWriter, request *http.Request) error
	GetScans(writer http.ResponseWriter, request *http.Request) error
	CancelScanByID(w http.ResponseWriter, r *http.Request) error
	GetScanInsightsByID(w http.ResponseWriter, r *http.Request) error
	GetScanVulnerabilitySummaryByID(w http.ResponseWriter, r *http.Request) error
	GetReports(w http.ResponseWriter, r *http.Request) error
	GetScoreCardTrends(w http.ResponseWriter, r *http.Request) error
}

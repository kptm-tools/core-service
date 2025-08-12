package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/lib/pq"
)

type ScanRepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.ScanRepository = (*ScanRepo)(nil)

func NewScanRepository(queries *repository.Queries) *ScanRepo {
	return &ScanRepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *ScanRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *ScanRepo) CreateScan(ctx context.Context, s domain.Scan) (*domain.Scan, error) {
	queries := r.getQueries(ctx)
	params := repository.CreateScanParams{
		TenantID:   s.TenantID,
		OperatorID: s.OperatorID,
		HostID:     s.HostID,
		Status:     repository.ScanStatus(s.Status),
		StartedAt:  sql.NullTime{Time: s.StartedAt, Valid: true},
	}
	dbScan, err := queries.CreateScan(ctx, params)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23503" && pqErr.Constraint == "scans_host_id_fkey" {
				return nil, customerrors.ErrHostNotFound
			}
		}
		return nil, err
	}
	domScan := toDomainScan(dbScan)
	return &domScan, nil
}

func (r *ScanRepo) GetScansForTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error) {
	queries := r.getQueries(ctx)
	dbScans, err := queries.ListScansForTenant(ctx, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []domain.ScanSummary{}, nil
		}
		return nil, err
	}

	scanSummaries := make([]domain.ScanSummary, len(dbScans))
	for i, dbScan := range dbScans {
		scanSummaries[i] = domain.ScanSummary{
			ScanID:          dbScan.ScanID,
			ScanDate:        dbScan.ScanDate.Time.Format(time.RFC822),
			Host:            dbScan.HostAlias,
			Duration:        dbScan.DurationInSeconds,
			Status:          string(dbScan.Status),
			Vulnerabilities: int(dbScan.TotalVulnerabilities),
			Severities: tools.SeverityCounts{
				Critical: int(dbScan.CriticalVulnerabilities),
				High:     int(dbScan.HighVulnerabilities),
				Medium:   int(dbScan.MediumVulnerabilities),
				Low:      int(dbScan.LowVulnerabilities),
				None:     int(dbScan.NoneVulnerabilities),
				Unknown:  int(dbScan.UnknownVulnerabilities),
			},
		}
	}
	return scanSummaries, nil
}

func (r *ScanRepo) GetScanByID(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
	queries := r.getQueries(ctx)
	dbScan, err := queries.GetScanByID(ctx, scanID)
	if err != nil {
		return nil, err
	}

	domScan := toDomainScan(dbScan)
	return &domScan, nil
}

func (r *ScanRepo) GetScanAssetsByID(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error) {
	queries := r.getQueries(ctx)
	dbScan, err := queries.GetAssetsByScanID(ctx, scanID)
	if err != nil {
		return nil, err
	}

	scanOSandServicesResults := make([]domain.ScanOSandServicesResult, len(dbScan))
	for i, scan := range dbScan {
		scanOSandServicesResults[i] = domain.ScanOSandServicesResult{
			AssetType:                 scan.AssetType,
			ID:                        scan.ID,
			HostID:                    scan.HostID,
			ScanID:                    scan.ScanID,
			Name:                      scan.Name.String,
			Version:                   scan.Version.String,
			Family:                    scan.Family.String,
			OsType:                    scan.OsType.String,
			Port:                      scan.Port.Int32,
			Protocol:                  scan.Protocol.String,
			Fingerprint:               scan.Fingerprint.String,
			Cpe:                       scan.Cpe.String,
			Product:                   scan.Product.String,
			Accuracy:                  scan.Accuracy.Int32,
			PortState:                 string(scan.PortState.PortStateEnum),
			TotalVulnerabilitiesCount: scan.TotalVulnerabilitiesCount,
			CriticalCount:             scan.CriticalCount,
			HighCount:                 scan.HighCount,
			MediumCount:               scan.MediumCount,
			LowCount:                  scan.LowCount,
			NoneCount:                 scan.NoneCount,
			UnknownCount:              scan.UnknownCount,
			CreatedAt:                 scan.CreatedAt.Time,
			UpdatedAt:                 scan.UpdatedAt.Time,
		}
	}
	return scanOSandServicesResults, nil
}

func (r *ScanRepo) GetScanInsightsBaseData(ctx context.Context, scanID uuid.UUID) (domain.ScanInsightsBaseData, error) {
	queries := r.getQueries(ctx)
	dbInsights, err := queries.GetScanInsights(ctx, scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ScanInsightsBaseData{}, customerrors.ErrScanNotFound
		}
		return domain.ScanInsightsBaseData{}, err
	}

	baseInsights := domain.ScanInsightsBaseData{
		ScanID:    dbInsights.ID,
		HostAlias: dbInsights.ScanAlias,
		ScanDate:  dbInsights.ScanDate.Time,

		TotalVulnerabilities:    int(dbInsights.TotalVulnerabilities),
		CriticalVulnerabilities: int(dbInsights.CriticalVulnerabilities),
		HighVulnerabilities:     int(dbInsights.HighVulnerabilities),
		MediumVulnerabilities:   int(dbInsights.MediumVulnerabilities),
		LowVulnerabilities:      int(dbInsights.LowVulnerabilities),
		NoneVulnerabilities:     int(dbInsights.NoneVulnerabilities),
		UnknownVulnerabilities:  int(dbInsights.UnknownVulnerabilities),

		SeverityPerTypeJSON: dbInsights.SeverityPerTypeMap,
	}

	return baseInsights, nil
}

func (r *ScanRepo) GetProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error) {
	queries := r.getQueries(ctx)
	score, err := queries.GetProtectionScoreForScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0.0, customerrors.ErrScanNotFound
		}
		return 0.0, err
	}
	return score, nil
}

func (r *ScanRepo) UpdateProtectionScore(ctx context.Context, scanID uuid.UUID, newScore float64) error {
	queries := r.getQueries(ctx)
	params := repository.UpdateProtectionScoreForScanParams{
		ProtectionScore: newScore,
		ID:              scanID,
	}
	if err := queries.UpdateProtectionScoreForScan(ctx, params); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return customerrors.ErrScanNotFound
		}
		return err
	}
	return nil
}

// GetPreviousScan gets the scan that came just before the scan with the specified ScanID, for that
// same host. It returns nil if no previous scan exists.
func (r *ScanRepo) GetPreviousScan(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
	queries := r.getQueries(ctx)
	dbScan, err := queries.GetPreviousScanOnHost(ctx, scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No previous scan exists
		}
		return nil, err
	}
	domScan := toDomainScan(dbScan)
	return &domScan, nil
}

func (r *ScanRepo) UpdateScanStatus(
	ctx context.Context,
	scanID uuid.UUID,
	status enums.ScanStatus,
) error {
	queries := r.getQueries(ctx)
	params := repository.UpdateScanStatusParams{
		Status: repository.ScanStatus(status.String()),
		ID:     scanID,
	}
	if err := queries.UpdateScanStatus(ctx, params); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return customerrors.ErrScanNotFound
		}
		return err
	}
	return nil
}

func (r *ScanRepo) UpdateScanStatusAndEndedAt(
	ctx context.Context,
	scanID uuid.UUID,
	status enums.ScanStatus,
	endedAt time.Time,
) error {
	queries := r.getQueries(ctx)
	params := repository.UpdateScanStatusAndEndedAtParams{
		Status:  repository.ScanStatus(status.String()),
		EndedAt: sql.NullTime{Time: endedAt, Valid: true},
		ID:      scanID,
	}
	if err := queries.UpdateScanStatusAndEndedAt(ctx, params); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return customerrors.ErrScanNotFound
		}
		return err
	}
	return nil
}

func (r *ScanRepo) GetReportsByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ReportItem, error) {
	queries := r.getQueries(ctx)
	dbReports, err := queries.GetReportsByTenantID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []domain.ReportItem{}, nil
		}
		return nil, err
	}

	reports := make([]domain.ReportItem, len(dbReports))
	for i, dbReport := range dbReports {
		reports[i] = domain.ReportItem{
			ScanID:          dbReport.ScanID,
			HostName:        dbReport.HostName.String,
			IP:              dbReport.Ip.String,
			ScanDate:        dbReport.ScanDate.Time,
			TotalSeverities: int(dbReport.TotalSeverities),
			CommentStatus:   domain.CommmentStatus(dbReport.CommentStatus),
		}
	}
	return reports, nil
}

func (r *ScanRepo) GetOldestScanByHostID(
	ctx context.Context,
	hostID uuid.UUID,
	fromDate *time.Time,
	toDate *time.Time,
) (*domain.Scan, error) {
	queries := r.getQueries(ctx)
	var sqlFromDate sql.NullTime
	if fromDate != nil {
		sqlFromDate = sql.NullTime{Time: *fromDate, Valid: true}
	}

	var sqlToDate sql.NullTime
	if toDate != nil {
		sqlToDate = sql.NullTime{Time: *toDate, Valid: true}
	}

	params := repository.GetOldestScanByHostIDParams{
		HostID:      hostID,
		StartedAt:   sqlFromDate,
		StartedAt_2: sqlToDate,
	}
	dbScan, err := queries.GetOldestScanByHostID(ctx, params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No scan found for this host, but the host exists
		}
		return nil, err
	}
	domScan := toDomainScan(dbScan)
	return &domScan, nil
}

func (r *ScanRepo) GetLatestScanByHostID(
	ctx context.Context,
	hostID uuid.UUID,
	fromDate *time.Time,
	toDate *time.Time,
) (*domain.Scan, error) {
	queries := r.getQueries(ctx)

	var sqlFromDate sql.NullTime
	if fromDate != nil {
		sqlFromDate = sql.NullTime{Time: *fromDate, Valid: true}
	}

	var sqlToDate sql.NullTime
	if toDate != nil {
		sqlToDate = sql.NullTime{Time: *toDate, Valid: true}
	}

	params := repository.GetLatestScanByHostIDParams{
		HostID:      hostID,
		StartedAt:   sqlFromDate,
		StartedAt_2: sqlToDate,
	}
	dbScan, err := queries.GetLatestScanByHostID(ctx, params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No scan found for this host, but the host exists
		}
		return nil, err
	}
	domScan := toDomainScan(dbScan)
	return &domScan, nil
}

func toDomainScan(dbScan repository.Scan) domain.Scan {
	return domain.Scan{
		ID:              dbScan.ID,
		HostID:          dbScan.HostID,
		TenantID:        dbScan.TenantID,
		Status:          string(dbScan.Status),
		ProtectionScore: &dbScan.ProtectionScore,
		OperatorID:      dbScan.OperatorID,
		CreatedAt:       dbScan.CreatedAt.Time,
		UpdatedAt:       dbScan.UpdatedAt.Time,
		StartedAt:       dbScan.StartedAt.Time,
		EndedAt:         &dbScan.EndedAt.Time,
	}
}

package storage

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
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

func (r *ScanRepo) GetScanByID(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
	queries := r.getQueries(ctx)
	dbScan, err := queries.GetScanByID(ctx, scanID)
	if err != nil {
		return nil, err
	}
	domScan := toDomainScan(dbScan)
	return &domScan, nil
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

func toDomainScan(dbScan repository.Scan) domain.Scan {
	return domain.Scan{
		ID:         dbScan.ID,
		TenantID:   dbScan.TenantID,
		OperatorID: dbScan.OperatorID,
		CreatedAt:  dbScan.CreatedAt.Time,
		UpdatedAt:  dbScan.UpdatedAt.Time,
		StartedAt:  dbScan.StartedAt.Time,
		EndedAt:    &dbScan.EndedAt.Time,
	}
}

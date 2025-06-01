package storage

import (
	"context"

	"github.com/google/uuid"
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

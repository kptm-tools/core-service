package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	tools2 "github.com/kptm-tools/common/common/pkg/results/tools"

	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/sqlc-dev/pqtype"
)

type ScanResultsRepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.ScanResultRepository = (*ScanResultsRepo)(nil)

func NewScanResultRepository(queries *repository.Queries) *ScanResultsRepo {
	return &ScanResultsRepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *ScanResultsRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *ScanResultsRepo) CreateScanResult(ctx context.Context, sr domain.ScanResult) error {
	queries := r.getQueries(ctx)

	resultBytes, err := json.Marshal(sr.Result.Result)
	if err != nil {
		return fmt.Errorf("error marshalling scan result: %w", err)
	}
	params := repository.CreateScanResultParams{
		ScanID:  sr.ScanID,
		Tool:    repository.ToolEnum(sr.Result.Tool.String()),
		Success: sr.Success,
		Result:  pqtype.NullRawMessage{RawMessage: resultBytes, Valid: true},
	}
	queries.CreateScanResult(ctx, params)

	return nil
}

func (r *ScanResultsRepo) GetScanResultsByScanID(ctx context.Context, scanID uuid.UUID, tools []string) ([]domain.ScanResult, error) {
	queries := r.getQueries(ctx)

	params := repository.GetScanResultsByScanIDParams{
		ScanID:  scanID,
		Column2: make([]repository.ToolEnum, 0, len(tools)),
	}
	for _, t := range tools {
		params.Column2 = append(params.Column2, repository.ToolEnum(t))
	}
	dbResults, err := queries.GetScanResultsByScanID(ctx, params)
	if err != nil {
		return nil, err
	}

	scanResults := make([]domain.ScanResult, len(dbResults))
	for i, db := range dbResults {
		scanResults[i] = domain.ScanResult{
			ScanID:  db.ScanID,
			Success: db.Success,
			Result:  tools2.ToolResult{},
		}
	}
	return scanResults, nil
}

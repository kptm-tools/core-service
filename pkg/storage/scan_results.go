package storage

import (
	"context"
	"encoding/json"
	"fmt"

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

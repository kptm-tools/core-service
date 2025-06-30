package storage

import (
	"context"
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type WASCRepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.WASCRepository = (*WASCRepo)(nil)

func NewWASCRepository(queries *repository.Queries) *WASCRepo {
	return &WASCRepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *WASCRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *WASCRepo) CreateOrUpdateWASC(ctx context.Context, webVuln tools.WebVulnerability) (*repository.WascDetail, error) {
	if webVuln.WascID == "" {
		return nil, nil
	}

	queries := r.getQueries(ctx)

	params := repository.CreateOrUpdateWASCDetailParams{
		WascID:      webVuln.WascID,
		Title:       "",
		Description: "",
		LastUpdated: time.Now(),
	}

	dbCWE, err := queries.CreateOrUpdateWASCDetail(ctx, params)
	if err != nil {
		return nil, err
	}

	return &repository.WascDetail{
		WascID:      dbCWE.WascID,
		Title:       dbCWE.Title,
		Description: dbCWE.Description,
		LastUpdated: dbCWE.LastUpdated,
	}, nil
}

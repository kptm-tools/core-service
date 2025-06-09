package storage

import (
	"context"
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type CWERepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.CWERepository = (*CWERepo)(nil)

func NewCWERepository(queries *repository.Queries) *CWERepo {
	return &CWERepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *CWERepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *CWERepo) CreateOrUpdateCWE(ctx context.Context, vuln tools.Vulnerability) (*repository.CweDetail, error) {
	queries := r.getQueries(ctx)

	// --- Extract the CWE from the Vulnerability payload

	// TODO: Fill this with the new remediation struct that must come with a vuln
	params := repository.CreateOrUpdateCWEDetailParams{
		CweID:           vuln.Type.String(),
		Title:           "",
		MitigationPhase: "Example mitigation Phase",
		Description:     "Example description",
		LastUpdated:     time.Now().UTC(),
	}

	// 1. Store the CWE record

	cwe, err := queries.CreateOrUpdateCWEDetail(ctx, params)
	if err != nil {
		return nil, err
	}
	return &cwe, nil
}

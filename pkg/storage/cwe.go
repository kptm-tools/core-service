package storage

import (
	"context"
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/interfaces"
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

func (r *CWERepo) CreateOrUpdateCWE(ctx context.Context, cwe tools.CWERemediation) (*tools.CWERemediation, error) {
	queries := r.getQueries(ctx)

	// --- Extract the CWE from the payload
	var phase string
	if len(cwe.Phase) > 0 {
		phase = cwe.Phase[0]
	} else {
		phase = ""
	}

	params := repository.CreateOrUpdateCWEDetailParams{
		CweID:              cwe.ID,
		Title:              cwe.Title,
		MitigationPhase:    phase,
		Description:        cwe.Description,
		Effectiveness:      cwe.Effectiveness,
		EffectivenessNotes: cwe.EffectivenessNotes,
		LastUpdated:        time.Now().UTC(),
	}

	// 1. Store the CWE record
	dbCWE, err := queries.CreateOrUpdateCWEDetail(ctx, params)
	if err != nil {
		return nil, err
	}
	return &tools.CWERemediation{
		ID:                 dbCWE.CweID,
		Title:              dbCWE.Title,
		Phase:              []string{dbCWE.MitigationPhase},
		Description:        dbCWE.Description,
		Effectiveness:      dbCWE.Effectiveness,
		EffectivenessNotes: dbCWE.EffectivenessNotes,
		LastUpdated:        dbCWE.LastUpdated,
	}, nil
}

func (r *CWERepo) CreateCWERemediation(ctx context.Context, remediation *tools.CWERemediation) (*tools.CWERemediation, error) {
	queries := r.getQueries(ctx)

	params := repository.CreateOrUpdateCWEDetailParams{
		CweID:              remediation.ID,
		Title:              remediation.Title,
		MitigationPhase:    "",
		Description:        remediation.Description,
		Effectiveness:      remediation.Effectiveness,
		EffectivenessNotes: remediation.EffectivenessNotes,
		LastUpdated:        time.Now().UTC(),
	}

	dbCWE, err := queries.CreateOrUpdateCWEDetail(ctx, params)
	if err != nil {
		return nil, err
	}

	return &tools.CWERemediation{
		ID:                 dbCWE.CweID,
		Title:              dbCWE.Title,
		Phase:              []string{dbCWE.MitigationPhase},
		Description:        dbCWE.Description,
		Effectiveness:      dbCWE.Effectiveness,
		EffectivenessNotes: dbCWE.EffectivenessNotes,
		LastUpdated:        dbCWE.LastUpdated,
	}, nil
}

func (r *CWERepo) GetCWERemediationByID(ctx context.Context, mitigationID string) (*tools.CWERemediation, error) {
	queries := r.getQueries(ctx)

	dbCWE, err := queries.GetCWEDetailByID(ctx, mitigationID)
	if err != nil {
		return nil, err
	}

	return &tools.CWERemediation{
		ID:                 dbCWE.CweID,
		Title:              dbCWE.Title,
		Phase:              []string{dbCWE.MitigationPhase},
		Description:        dbCWE.Description,
		Effectiveness:      dbCWE.Effectiveness,
		EffectivenessNotes: dbCWE.EffectivenessNotes,
		LastUpdated:        dbCWE.LastUpdated,
	}, nil
}

func (r *CWERepo) GetCWERemediationsByCWEID(ctx context.Context, cweID string) ([]tools.CWERemediation, error) {
	queries := r.getQueries(ctx)

	dbCWEs, err := queries.GetCWEDetailsByCWEID(ctx, cweID)
	if err != nil {
		return nil, err
	}

	remediations := make([]tools.CWERemediation, len(dbCWEs))
	for i, dbCWE := range dbCWEs {
		remediations[i] = tools.CWERemediation{
			ID:                 dbCWE.CweID,
			Title:              dbCWE.Title,
			Phase:              []string{dbCWE.MitigationPhase},
			Description:        dbCWE.Description,
			Effectiveness:      dbCWE.Effectiveness,
			EffectivenessNotes: dbCWE.EffectivenessNotes,
			LastUpdated:        dbCWE.LastUpdated,
		}
	}

	return remediations, nil
}

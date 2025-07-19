package storage

import (
	"context"
	"database/sql"
	"github.com/kptm-tools/core-service/pkg/domain"
	"strconv"
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

func (r *CWERepo) CreateOrUpdateCWE(ctx context.Context, cwe domain.CWEDetail) (*domain.CWEDetail, error) {
	if cwe.ID == "" {
		return nil, nil
	}

	queries := r.getQueries(ctx)

	params := repository.CreateOrUpdateCWEDetailParams{
		CweID:       cwe.ID,
		Title:       cwe.Title,
		Description: cwe.Description,
		LastUpdated: time.Now(),
	}

	dbCWE, err := queries.CreateOrUpdateCWEDetail(ctx, params)
	if err != nil {
		return nil, err
	}

	return &domain.CWEDetail{
		ID:          dbCWE.CweID,
		Title:       dbCWE.Title,
		Description: dbCWE.Description,
		LastUpdated: &dbCWE.LastUpdated,
	}, nil
}

func (r *CWERepo) CreateCWERemediation(ctx context.Context, remediation *tools.CWERemediation) (*tools.CWERemediation, error) {
	queries := r.getQueries(ctx)

	params := repository.CreateCWERemediationParams{
		CweID:              remediation.ID,
		MitigationID:       sql.NullString{Valid: false},
		Phase:              "",
		Description:        remediation.Description,
		Effectiveness:      sql.NullString{Valid: false},
		EffectivenessNotes: sql.NullString{Valid: false},
		CreatedAt:          sql.NullTime{Valid: false},
	}

	if len(remediation.Phase) > 0 {
		params.Phase = remediation.Phase[0]
	}

	if remediation.MitigationID != "" {
		params.MitigationID = sql.NullString{String: remediation.MitigationID, Valid: true}
	}

	if remediation.Effectiveness != "" {
		params.Effectiveness = sql.NullString{String: remediation.Effectiveness, Valid: true}
	}

	if remediation.EffectivenessNotes != "" {
		params.EffectivenessNotes = sql.NullString{String: remediation.EffectivenessNotes, Valid: true}
	}

	if !remediation.LastUpdated.IsZero() {
		params.CreatedAt = sql.NullTime{Time: remediation.LastUpdated, Valid: true}
	}

	dbCWE, err := queries.CreateCWERemediation(ctx, params)
	if err != nil {
		return nil, err
	}

	return &tools.CWERemediation{
		ID:                 dbCWE.CweID,
		MitigationID:       dbCWE.MitigationID.String,
		Phase:              []string{dbCWE.Phase},
		Description:        dbCWE.Description,
		Effectiveness:      dbCWE.Effectiveness.String,
		EffectivenessNotes: dbCWE.EffectivenessNotes.String,
		LastUpdated:        dbCWE.CreatedAt.Time,
	}, nil
}

func (r *CWERepo) GetCWERemediationByID(ctx context.Context, mitigationID string) (*tools.CWERemediation, error) {
	queries := r.getQueries(ctx)

	idInt32, err := strconv.ParseInt(mitigationID, 10, 32)
	if err != nil {
		return nil, err
	}

	dbCWE, err := queries.GetCWEDetailByID(ctx, int32(idInt32))
	if err != nil {
		return nil, err
	}

	return &tools.CWERemediation{
		ID:                 dbCWE.CweID,
		MitigationID:       dbCWE.MitigationID.String,
		Phase:              []string{dbCWE.Phase},
		Description:        dbCWE.Description,
		Effectiveness:      dbCWE.Effectiveness.String,
		EffectivenessNotes: dbCWE.EffectivenessNotes.String,
		LastUpdated:        dbCWE.CreatedAt.Time,
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
			MitigationID:       dbCWE.MitigationID.String,
			Phase:              []string{dbCWE.Phase},
			Description:        dbCWE.Description,
			Effectiveness:      dbCWE.Effectiveness.String,
			EffectivenessNotes: dbCWE.EffectivenessNotes.String,
			LastUpdated:        dbCWE.CreatedAt.Time,
		}
	}

	return remediations, nil
}

func (r *CWERepo) GetCWEDetailWithMitigationsByID(ctx context.Context, cweID string) ([]domain.CWEDetailWithMitigations, error) {
	queries := r.getQueries(ctx)

	dbCWEs, err := queries.GetCWEDetailWithMitigationsByID(ctx, cweID)
	if err != nil {
		return nil, err
	}

	remediationDetails := make([]domain.CWEDetailWithMitigations, len(dbCWEs))
	for i, dbCWE := range dbCWEs {

		remediationDetails[i] = domain.CWEDetailWithMitigations{
			CweID:                 dbCWE.CweID,
			Title:                 dbCWE.Title,
			Description:           dbCWE.Description,
			MitigationID:          dbCWE.MitigationID.String,
			Phase:                 dbCWE.Phase.String,
			MitigationDescription: dbCWE.MitigationDescription.String,
			Effectiveness:         dbCWE.Effectiveness.String,
			EffectivenessNotes:    dbCWE.EffectivenessNotes.String,
			MigrationCreatedAt:    dbCWE.MitigationCreatedAt.Time,
		}
	}
	return remediationDetails, nil
}

func (r *CWERepo) CreateOrUpdateCWEFromWebVulnerability(ctx context.Context, vuln tools.WebVulnerability) (*tools.CWERemediation, error) {
	if vuln.CweID == "" {
		return nil, nil
	}

	queries := r.getQueries(ctx)

	params := repository.CreateOrUpdateCWEDetailParams{
		CweID:       vuln.CweID,
		Title:       "",
		Description: "",
		LastUpdated: time.Now(),
	}
	dbCWE, err := queries.CreateOrUpdateCWEDetail(ctx, params)
	if err != nil {
		return nil, err
	}

	return &tools.CWERemediation{
		ID:          dbCWE.CweID,
		Title:       dbCWE.Title,
		Description: dbCWE.Description,
		LastUpdated: dbCWE.LastUpdated,
	}, nil
}

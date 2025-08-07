package storage

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"github.com/kptm-tools/core-service/pkg/domain"

	"github.com/kptm-tools/common/common/pkg/enums"
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

// CreateOrUpdateCWE method removed - no longer needed with pre-populated CWE approach

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
			OwaspTop10Category:    dbCWE.OwaspTop10Category.String,
			MitigationID:          dbCWE.MitigationID.String,
			Phase:                 dbCWE.Phase.String,
			MitigationDescription: dbCWE.MitigationDescription.String,
			Effectiveness:         dbCWE.Effectiveness.String,
			EffectivenessNotes:    dbCWE.EffectivenessNotes.String,
			MitigationCreatedAt:   dbCWE.MitigationCreatedAt.Time,
		}
	}
	return remediationDetails, nil
}

// CreateOrUpdateCWEFromWebVulnerability method removed - no longer needed with pre-populated CWE approach

// New methods for refactored approach

// GetCWEByID retrieves a CWE detail by its ID from the pre-populated database
func (r *CWERepo) GetCWEByID(ctx context.Context, cweID string) (*domain.CWEDetail, error) {
	queries := r.getQueries(ctx)

	dbCWE, err := queries.GetCWEDetailByCWEID(ctx, cweID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // CWE not found
		}
		return nil, err
	}

	return &domain.CWEDetail{
		ID:                 dbCWE.CweID,
		Title:              dbCWE.Title,
		Description:        dbCWE.Description,
		LastUpdated:        &dbCWE.LastUpdated,
		OwaspTop10Category: dbCWE.OwaspTop10Category.String,
	}, nil
}

// CWEExists checks if a CWE exists in the pre-populated database
func (r *CWERepo) CWEExists(ctx context.Context, cweID string) (bool, error) {
	cwe, err := r.GetCWEByID(ctx, cweID)
	if err != nil {
		return false, err
	}
	return cwe != nil, nil
}

// CreateCWEStub creates a minimal CWE record for unknown CWE IDs (Option A)
func (r *CWERepo) CreateCWEStub(ctx context.Context, cweID string) (*domain.CWEDetail, error) {
	queries := r.getQueries(ctx)

	// Create a stub record with minimal information
	params := repository.CreateOrUpdateCWEDetailParams{
		CweID:              cweID,
		Title:              "Unknown Weakness",
		Description:        "This CWE ID was not found in the pre-populated knowledge base. Manual review recommended.",
		LastUpdated:        time.Now().UTC(),
		OwaspTop10Category: sql.NullString{String: enums.OwaspCategoryNoInfo.String(), Valid: true},
	}

	dbCWE, err := queries.CreateOrUpdateCWEDetail(ctx, params)
	if err != nil {
		return nil, err
	}

	return &domain.CWEDetail{
		ID:                 dbCWE.CweID,
		Title:              dbCWE.Title,
		Description:        dbCWE.Description,
		LastUpdated:        &dbCWE.LastUpdated,
		OwaspTop10Category: dbCWE.OwaspTop10Category.String,
	}, nil
}

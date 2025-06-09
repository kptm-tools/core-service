package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type OSRepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.OSRepository = (*OSRepo)(nil)

func NewOSRepository(queries *repository.Queries) *OSRepo {
	return &OSRepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *OSRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *OSRepo) CreateOS(
	ctx context.Context,
	hostID uuid.UUID,
	scanID uuid.UUID,
	osData tools.OSData,
) (*domain.OperatingSystem, error) {
	params := repository.CreateOSParams{
		HostID: hostID,
		ScanID: scanID,
		OsName: sql.NullString{String: osData.Name, Valid: osData.Name != ""},
		Family: sql.NullString{String: osData.Family, Valid: osData.Family != ""},
		OsType: sql.NullString{String: osData.Type, Valid: osData.Type != ""},
	}
	queries := r.getQueries(ctx)

	dbOS, err := queries.CreateOS(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to insert operating system using sqlc: %w", err)
	}

	domOS := toDomainOS(dbOS)

	return &domOS, nil
}

func (r *OSRepo) GetOSByID(ctx context.Context, osID int32) (*domain.OperatingSystem, error) {
	queries := r.getQueries(ctx)
	dbOS, err := queries.GetOSByID(ctx, osID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrOSNotFound
		}
		return nil, fmt.Errorf("failed to query operating system: %w", err)
	}
	domOS := toDomainOS(dbOS)

	return &domOS, nil
}

// toDomainOperatingSystem transforms a repository.OperatingSystem into a domain.OperatingSystem.
// It handles the conversion of sql.Null* types to their Go native types,
// providing zero values for fields that are NULL in the database.
func toDomainOS(dbOS repository.OperatingSystem) domain.OperatingSystem {
	return domain.OperatingSystem{
		ID:          dbOS.ID,
		HostID:      dbOS.HostID,
		ScanID:      dbOS.ScanID,
		OSName:      dbOS.OsName.String, // .String for sql.NullString
		Family:      dbOS.Family.String,
		OSType:      dbOS.OsType.String,
		Fingerprint: dbOS.Fingerprint.String,
		CPE:         dbOS.Cpe.String,
		Accuracy:    dbOS.Accuracy.Int32, // .Int32 for sql.NullInt32
		CreatedAt:   dbOS.CreatedAt.Time, // .Time for sql.NullTime
		UpdatedAt:   dbOS.UpdatedAt.Time,
	}
}

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/sqlc-dev/pqtype"
)

type HostRepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.HostRepository = (*HostRepo)(nil)

func NewHostRepository(queries *repository.Queries) *HostRepo {
	return &HostRepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *HostRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *HostRepo) CreateHost(ctx context.Context, host *domain.Host) (*domain.Host, error) {
	queries := r.getQueries(ctx)
	rapporteursBytes, err := json.Marshal(host.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rapporteurs slice into bytes: %w", err)
	}

	// 1. Insert into host
	dbHost, err := queries.CreateHost(ctx, repository.CreateHostParams{
		TenantID:    host.TenantID,
		OperatorID:  host.OperatorID,
		Domain:      sql.NullString{String: host.Domain, Valid: host.Domain != ""},
		Ip:          sql.NullString{String: host.IP, Valid: host.IP != ""},
		Alias:       host.Name,
		Rapporteurs: pqtype.NullRawMessage{RawMessage: rapporteursBytes, Valid: len(rapporteursBytes) != 0},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	// 2. Insert credentials
	dbCredentials := make([]repository.Credential, len(host.Credentials))
	for i, credential := range host.Credentials {
		dbCred, err := queries.CreateCredential(ctx, repository.CreateCredentialParams{
			HostID:   dbHost.ID,
			Username: credential.Username,
			Password: credential.Password,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to insert credential: %w", err)
		}
		dbCredentials[i] = dbCred
	}

	return toDomainHost(dbHost, dbCredentials), nil
}

func (r *HostRepo) GetHostByID(ctx context.Context, hostID uuid.UUID) (*domain.Host, error) {
	queries := r.getQueries(ctx)
	dbHost, err := queries.GetHostByID(ctx, hostID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrHostNotFound
		}
		return nil, err
	}
	domHost := toDomainHost(dbHost, []repository.Credential{})
	return domHost, nil
}

func (r *HostRepo) GetHostsByTenantID(
	ctx context.Context,
	tenantID uuid.UUID,
	hostsIDFilter []uuid.UUID,
) ([]*domain.Host, error) {
	queries := r.getQueries(ctx)

	var (
		dbHosts []repository.Host
		err     error
	)
	if len(hostsIDFilter) == 0 {
		dbHosts, err = queries.GetHostsByTenantID(ctx, tenantID)
	} else {
		params := repository.GetHostsByTenantIDAndHostsFilterParams{
			TenantID:      tenantID,
			HostsIDFilter: hostsIDFilter,
		}
		dbHosts, err = queries.GetHostsByTenantIDAndHostsFilter(ctx, params)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch db hosts by tenantID: %w", err)
	}
	slog.Debug("Got tenant hosts", slog.Any("hosts", dbHosts))

	domHosts := make([]*domain.Host, len(dbHosts))
	for i, dbHost := range dbHosts {
		domHosts[i] = toDomainHost(dbHost, []repository.Credential{})
	}
	return domHosts, nil
}

func (r *HostRepo) PatchHostByID(ctx context.Context, h domain.Host) (*domain.Host, error) {
	queries := r.getQueries(ctx)
	// 1. Patch the host
	rapporteursBytes, err := json.Marshal(h.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("faield to marshal host rapporteurs: %w", err)
	}
	dbHost, err := queries.PatchHostByID(ctx, repository.PatchHostByIDParams{
		ID:          h.ID,
		Domain:      sql.NullString{String: h.Domain, Valid: h.Domain != ""},
		Ip:          sql.NullString{String: h.IP, Valid: h.IP != ""},
		Alias:       h.Name,
		Rapporteurs: rapporteursBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to patch host by id %s: %w", h.ID.String(), err)
	}

	// 2. Patch the credentials
	// 2.1 Delete previous credentials
	_, err = queries.DeleteCredentialsByHostID(ctx, dbHost.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete credentials for host: %w", err)
	}
	// 2.2 Create a new record for each new credential
	domainCredentials := make([]domain.Credential, len(h.Credentials))
	for i, cred := range h.Credentials {
		createdCred, err := queries.CreateCredential(ctx, repository.CreateCredentialParams{
			HostID:   dbHost.ID,
			Username: cred.Username,
			Password: cred.Password,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create credential reord for host %s: %w", h.ID.String(), err)
		}
		domainCred := domain.Credential{HostID: h.ID.String(), Username: createdCred.Username, Password: createdCred.Password}
		domainCredentials[i] = domainCred
	}
	// Fetch and assign updated credentials
	domHost := domain.Host{
		ID:          dbHost.ID,
		TenantID:    dbHost.TenantID,
		OperatorID:  dbHost.OperatorID,
		Name:        dbHost.Alias,
		Domain:      dbHost.Domain.String,
		IP:          dbHost.Ip.String,
		Credentials: domainCredentials,
		Rapporteurs: h.Rapporteurs,
		CreatedAt:   h.CreatedAt,
		UpdatedAt:   h.UpdatedAt,
	}
	return &domHost, nil
}

func (r *HostRepo) DeleteHostByID(ctx context.Context, hostID uuid.UUID) (bool, error) {
	queries := r.getQueries(ctx)
	rowsAffected, err := queries.DeleteHostByID(ctx, hostID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, customerrors.ErrHostNotFound
		}
		return false, fmt.Errorf("failed to delete host by id %s: %w", hostID.String(), err)
	}
	return rowsAffected >= 1, nil
}

func (r *HostRepo) AliasExists(ctx context.Context, alias string) (bool, error) {
	queries := r.getQueries(ctx)
	return queries.AliasExists(ctx, alias)
}

func toDomainHost(dbHost repository.Host, dbCredentials []repository.Credential) *domain.Host {
	host := domain.Host{
		ID:         dbHost.ID,
		TenantID:   dbHost.TenantID,
		OperatorID: dbHost.OperatorID,
		Name:       dbHost.Alias,
		Domain:     dbHost.Domain.String,
		IP:         dbHost.Ip.String,
		CreatedAt:  dbHost.CreatedAt.Time,
		UpdatedAt:  dbHost.UpdatedAt.Time,
	}

	domainCredentials := make([]domain.Credential, len(dbCredentials))
	for i, dbCred := range dbCredentials {
		domainCredentials[i] = domain.Credential{
			HostID:   dbHost.ID.String(),
			Username: dbCred.Username,
			Password: dbCred.Password,
		}
	}
	host.Credentials = domainCredentials

	if dbHost.Rapporteurs.Valid {
		if err := json.Unmarshal(dbHost.Rapporteurs.RawMessage, &host.Rapporteurs); err != nil {
			slog.Error("failed to unmarshal dbHost rapporteurs", slog.Any("error", err))
			return nil
		}
	} else {
		host.Rapporteurs = []domain.Rapporteur{}
	}
	return &host
}

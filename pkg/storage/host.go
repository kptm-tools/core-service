package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/repository"
	"github.com/sqlc-dev/pqtype"
)

func (s *PostgreSQLStore) ClearHostsTable() error {
	query := `TRUNCATE TABLE hosts RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to clear hosts table: %w", err)
	}

	return nil
}

func (s *PostgreSQLStore) CreateHost(ctx context.Context, t *domain.Host) (*domain.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction %w", err)
	}
	defer tx.Rollback()
	qtx := s.queries.WithTx(tx)

	rapporteursBytest, err := json.Marshal(t.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal repporteurs slice into bytes: %w", err)
	}

	// 1. Insert into host
	host, err := qtx.CreateHost(ctx, repository.CreateHostParams{
		TenantID:    t.TenantID,
		OperatorID:  t.OperatorID,
		Domain:      sql.NullString{String: t.Domain, Valid: t.Domain != ""},
		Ip:          sql.NullString{String: t.IP, Valid: t.IP != ""},
		Alias:       t.Name,
		Rapporteurs: pqtype.NullRawMessage{RawMessage: rapporteursBytest, Valid: len(rapporteursBytest) != 0},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	// 2. Insert credentials
	dbCredentials := make([]repository.Credential, len(t.Credentials))
	for i, credential := range t.Credentials {
		dbCred, err := qtx.CreateCredential(ctx, repository.CreateCredentialParams{
			HostID:   host.ID,
			Username: credential.Username,
			Password: credential.Password,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to insert credential: %w", err)
		}
		dbCredentials[i] = dbCred
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return toDomainHost(host, dbCredentials), nil
}

func (s *PostgreSQLStore) GetHostsByTenantID(
	ctx context.Context,
	tenantID uuid.UUID,
	hostsIDFilter []uuid.UUID,
) ([]*domain.Host, error) {
	var hosts []repository.Host
	var err error
	if len(hostsIDFilter) == 0 {
		hosts, err = s.queries.GetHostsByTenantID(ctx, tenantID)
	} else {
		params := repository.GetHostsByTenantIDAndHostsFilterParams{
			TenantID:      tenantID,
			HostsIDFilter: hostsIDFilter,
		}
		hosts, err = s.queries.GetHostsByTenantIDAndHostsFilter(ctx, params)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch db hosts by tenantID: %w", err)
	}

	slog.Debug("Got tenant hosts", slog.Any("hosts", hosts))

	domainHosts := make([]*domain.Host, len(hosts))
	for i, dbHost := range hosts {
		domainHosts[i] = toDomainHost(dbHost, []repository.Credential{})
	}
	return domainHosts, nil
}

func (s *PostgreSQLStore) GetHostByID(ctx context.Context, hostID uuid.UUID) (*domain.Host, error) {
	dbHost, err := s.queries.GetHostByID(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return toDomainHost(dbHost, []repository.Credential{}), nil
}

func (s *PostgreSQLStore) PatchHostByID(ctx context.Context, h *domain.Host) (*domain.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	qtx := s.queries.WithTx(tx)
	// 1. Patch the host
	rapporteursBytes, err := json.Marshal(h.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("faield to marshal host rapporteurs: %w", err)
	}
	host, err := qtx.PatchHostByID(ctx, repository.PatchHostByIDParams{
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
	_, err = qtx.DeleteCredentialsByHostID(ctx, h.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete credentials for host: %w", err)
	}
	// 2.2 Create a new record for each new credential
	domainCredentials := make([]domain.Credential, len(h.Credentials))
	for i, cred := range h.Credentials {
		createdCred, err := qtx.CreateCredential(ctx, repository.CreateCredentialParams{
			HostID:   h.ID,
			Username: cred.Username,
			Password: cred.Password,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create credential reord for host %s: %w", h.ID.String(), err)
		}
		domainCred := domain.Credential{HostID: h.ID.String(), Username: createdCred.Username, Password: createdCred.Password}
		domainCredentials[i] = domainCred
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Fetch and assign updated credentials
	domainHost := domain.Host{
		ID:          host.ID,
		TenantID:    host.TenantID,
		OperatorID:  host.OperatorID,
		Name:        host.Alias,
		Domain:      host.Domain.String,
		IP:          host.Ip.String,
		Credentials: domainCredentials,
		Rapporteurs: h.Rapporteurs,
		CreatedAt:   h.CreatedAt,
		UpdatedAt:   h.UpdatedAt,
	}

	return &domainHost, nil
}

func (s *PostgreSQLStore) GetCredentials(ctx context.Context, hostID uuid.UUID) ([]repository.Credential, error) {
	return s.queries.GetCredentialsByHostID(ctx, hostID)
}

func (s *PostgreSQLStore) DeleteHostByID(ID uuid.UUID) (bool, error) {
	query := `
    DELETE 
    FROM hosts
    WHERE id=$1
  `
	res, err := s.db.Exec(query, ID)

	switch err {
	case nil:
		count, _ := res.RowsAffected()
		return count == 1, nil
	default:
		return false, err
	}
}

func (s *PostgreSQLStore) ExistAlias(alias string) (bool, error) {
	var exists bool
	query := `SELECT 
    EXISTS(SELECT 1 FROM hosts WHERE alias = $1)
  `
	err := s.db.QueryRow(query, alias).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to verify existence: %w", err)
	}
	return exists, nil
}

func (s *PostgreSQLStore) GetHostVulnerabilityTrends(
	hostID uuid.UUID,
	timePeriodFilter domain.TimePeriodFilter,
	severityFilters []string,
) ([]domain.ServiceTimePeriod, error) {
	// This query is kind of complicated, but what it does is fill out time_periods and labels,
	// even when there is no data for said time_period. E.g: we only have data
	// for February, but we want to have the counts for other months to be 0 too.
	// It also has a CTE called ScanPeriods, which identifies if there was a scan at all
	// during that period. This allows us to differentiate if we got a 0 count because there
	// are no vulnerabilities, or because there is no scan.
	baseTrendQuery := `
		WITH TimePeriods AS (
			SELECT
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(date_series, 'FMMonth')
					WHEN $2 = 'Quarter' THEN 'Q' || TO_CHAR(date_series, 'Q')
					WHEN $2 = 'Semester' THEN 'Semester ' || CASE WHEN TO_CHAR(date_series, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE 'Unknown Period'
				END AS time_period_label,
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(date_series, 'YYYY-MM')
					WHEN $2 = 'Quarter' THEN TO_CHAR(date_series, 'YYYY-Q')
					WHEN $2 = 'Semester' THEN CASE WHEN TO_CHAR(date_series, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE '1'
				END AS ordering_period,
				date_series
			FROM generate_series(
				DATE_TRUNC('year', CURRENT_DATE),
				DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '1 year' - INTERVAL '1 day',
				CASE
					WHEN $2 = 'Month' THEN INTERVAL '1 month'
					WHEN $2 = 'Quarter' THEN INTERVAL '3 month'
					WHEN $2 = 'Semester' THEN INTERVAL '6 month'
					ELSE INTERVAL '1 month'
				END
			) AS date_series
		),
		ScanPeriods AS (
			SELECT
        DISTINCT ON (time_period_label)
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(s.started_at, 'FMMonth')
					WHEN $2 = 'Quarter' THEN 'Q' || TO_CHAR(s.started_at, 'Q')
					WHEN $2 = 'Semester' THEN 'Semester ' || CASE WHEN TO_CHAR(s.started_at, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE 'Unknown Period'
				END AS time_period_label,
				s.id AS scan_id,
				s.started_at AS scan_started_at
			FROM scans s
			WHERE s.host_id = $1
				AND EXTRACT(YEAR FROM s.started_at) = EXTRACT(YEAR FROM CURRENT_DATE)
      ORDER BY time_period_label, s.started_at DESC
		),
		VulnerabilityCounts AS (
			SELECT
				sp.time_period_label,
				COUNT(sv.id) AS vulnerability_count
			FROM ScanPeriods sp
			LEFT JOIN scan_vulnerabilities sv ON sv.scan_id = sp.scan_id
			INNER JOIN scans s ON sp.scan_id = s.id
			WHERE s.host_id = $1
				AND EXTRACT(YEAR FROM s.started_at) = EXTRACT(YEAR FROM CURRENT_DATE)
				-- Severity Filter Dynamic Condition goes here
				%s
			GROUP BY sp.time_period_label
		)
		SELECT
			tp.time_period_label AS time_period,
			vc.vulnerability_count AS vulnerability_count -- Now vc.vulnerability_count will be NULL if no scan
		FROM TimePeriods tp
		LEFT JOIN ScanPeriods sp ON tp.time_period_label = sp.time_period_label -- Join with ScanPeriods to ensure time period has a scan
		LEFT JOIN VulnerabilityCounts vc ON tp.time_period_label = vc.time_period_label
		ORDER BY tp.ordering_period;
	`

	trendQueryParams := []any{hostID, timePeriodFilter.String()}
	trendSeverityWhereClause, trendQueryParams := s.buildSeverityWhereClause(severityFilters, trendQueryParams)
	forattedTrendQuery := fmt.Sprintf(baseTrendQuery, trendSeverityWhereClause)
	slog.Debug("Executing Host Trend Query",
		slog.Any("query_params", trendQueryParams))

	trendsRows, err := s.db.Query(forattedTrendQuery, trendQueryParams...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability trends for host %d: %w", hostID, err)
	}
	defer trendsRows.Close()

	var timePeriods []domain.ServiceTimePeriod
	for trendsRows.Next() {
		var timePeriodData domain.ServiceTimePeriod
		if err := trendsRows.Scan(&timePeriodData.TimePeriod, &timePeriodData.VulnerabilityCount); err != nil {
			return nil, fmt.Errorf("failed to scan into time period: %w", err)
		}
		timePeriods = append(timePeriods, timePeriodData)
	}
	if trendsRows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate trend rows: %w", err)
	}
	return timePeriods, nil
}

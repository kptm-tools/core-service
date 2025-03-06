package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) ClearHostsTable() error {
	query := `TRUNCATE TABLE hosts RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to clear hosts table: %w", err)
	}

	return nil
}

func (s *PostgreSQLStore) CreateHost(t *domain.Host) (*domain.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction %w", err)
	}
	defer tx.Rollback()

	query := `
    INSERT INTO hosts (tenant_id, operator_id, domain, ip, alias, rapporteurs,  created_at, updated_at)
    values ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING id, tenant_id, operator_id, domain, ip, alias, rapporteurs, created_at, updated_at`

	rapporteursJSONB, err := json.Marshal(t.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rapporteurs: %w", err)
	}

	row := tx.QueryRow(query, t.TenantID, t.OperatorID, t.Domain, t.IP, t.Name, rapporteursJSONB, t.CreatedAt, t.UpdatedAt)
	newHost := &domain.Host{}

	if err := scanIntoHostRow(row, newHost); err != nil {
		return nil, fmt.Errorf("failed to insert host: %w", err)
	}

	if err := s.InsertCredentials(tx, newHost.ID, t.Credentials); err != nil {
		return nil, fmt.Errorf("failed to insert credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Retreive and assign credentials
	newHost.Credentials, err = s.GetCredentials(newHost.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	return newHost, nil
}

func (s *PostgreSQLStore) GetHostsByTenantID(tenantID string) ([]*domain.Host, error) {
	query := `
    SELECT *
    FROM hosts
    WHERE tenant_id=$1
  `

	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer rows.Close()

	hosts := []*domain.Host{}
	for rows.Next() {
		host := &domain.Host{}
		if err := scanIntoHost(rows, host); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}
		host.Credentials, err = s.GetCredentials(host.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch credentials: %w", err)
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (s *PostgreSQLStore) GetHostByID(hostID int) (*domain.Host, error) {
	query := `
  SELECT 
    id,
    tenant_id,
    operator_id,
    "domain",
    ip,
    alias,
    rapporteurs,
    created_at,
    updated_at
  FROM hosts
  WHERE id=$1;
  `
	var host domain.Host
	var rapporteursBytes []byte
	err := s.db.QueryRow(query, hostID).Scan(
		&host.ID,
		&host.TenantID,
		&host.OperatorID,
		&host.Domain,
		&host.IP,
		&host.Name,
		&rapporteursBytes,
		&host.CreatedAt,
		&host.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan into host: %w", err)
	}

	credentials, err := s.GetCredentials(hostID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	host.Credentials = credentials

	return &host, nil
}

func (s *PostgreSQLStore) PatchHostByID(h *domain.Host) (*domain.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
    UPDATE hosts
    SET  rapporteurs=$2, domain=$3, ip=$4, alias=$5
        WHERE id=$1
    RETURNING *
  `
	rapporteursJSONB, err := json.Marshal(h.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rapporteurs: %w", err)
	}

	row := tx.QueryRow(query, h.ID, rapporteursJSONB, h.Domain, h.IP, h.Name)
	host := &domain.Host{}
	if err := scanIntoHostRow(row, host); err != nil {
		return nil, fmt.Errorf("error fetching host: %w", err)
	}

	if err = s.UpdateCredentials(tx, host.ID, h.Credentials); err != nil {
		return nil, fmt.Errorf("failed to update credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Fetch and assign updated credentials
	credentials, err := s.GetCredentials(host.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated credentials: %w", err)
	}
	host.Credentials = credentials

	return host, nil
}

func (s *PostgreSQLStore) InsertCredentials(tx *sql.Tx, hostID int, credentials []domain.Credential) error {
	query := "INSERT INTO credentials (host_id, username, password) VALUES ($1, $2, pgp_sym_encrypt($3, 'MAMA', 'compress-algo=1, cipher-algo=aes256'))"
	for _, cred := range credentials {
		if _, err := tx.Exec(query, hostID, cred.Username, cred.Password); err != nil {
			return fmt.Errorf("failed to insert credential: %w", err)
		}
	}

	return nil
}

func (s *PostgreSQLStore) GetCredentials(hostID int) ([]domain.Credential, error) {
	query := `
    SELECT id, host_id, username,password
    FROM credentials
    WHERE host_id=$1
  `

	rows, err := s.db.Query(query, hostID)
	if err != nil {
		return nil, fmt.Errorf("error fetching Credentials: %w", err)
	}
	defer rows.Close()

	var credentials []domain.Credential
	for rows.Next() {
		credential, err := scanIntoCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		credentials = append(credentials, *credential)
	}

	if rows.Err() != nil {
		return nil, fmt.Errorf("error iterating sql rows: %w", err)
	}
	return credentials, nil
}

func (s *PostgreSQLStore) UpdateCredentials(tx *sql.Tx, hostID int, credentials []domain.Credential) error {
	// Step 1: Delete all credentials associated with the hostID
	deleteQuery := `DELETE FROM credentials WHERE host_id = $1`
	if _, err := tx.Exec(deleteQuery, hostID); err != nil {
		return fmt.Errorf("failed to delete existing credentials for hostID %d: %w", hostID, err)
	}

	insertQuery := `INSERT INTO credentials (host_id, username, password)
                  VALUES ($1, $2, pgp_sym_encrypt($3, 'MAMA', 'compress-algo=1, cipher-algo=aes256'))`

	for _, cred := range credentials {
		_, err := tx.Exec(insertQuery, hostID, cred.Username, cred.Password)
		if err != nil {
			return fmt.Errorf("failed to insert new credential for hostID %d: %w", hostID, err)
		}
	}
	return nil
}

func (s *PostgreSQLStore) DeleteHostByID(ID int) (bool, error) {
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

func scanIntoHost(rows *sql.Rows, host *domain.Host) error {
	var rapporteurs []byte
	if err := rows.Scan(&host.ID, &host.TenantID, &host.OperatorID, &host.Domain, &host.IP, &host.Name, &rapporteurs, &host.CreatedAt, &host.UpdatedAt); err != nil {
		return fmt.Errorf("error scanning rows: %w", err)
	}
	// Unmarshal the rapporteurs bytes
	if err := json.Unmarshal(rapporteurs, &host.Rapporteurs); err != nil {
		return fmt.Errorf("error unmarshalling rapporteurs: %w", err)
	}

	return nil
}

func scanIntoHostRow(row *sql.Row, host *domain.Host) error {
	var rapporteurs []byte
	if err := row.Scan(&host.ID, &host.TenantID, &host.OperatorID, &host.Domain, &host.IP, &host.Name, &rapporteurs, &host.CreatedAt, &host.UpdatedAt); err != nil {
		return fmt.Errorf("failed to scan host: %w", err)
	}
	if err := json.Unmarshal(rapporteurs, &host.Rapporteurs); err != nil {
		return fmt.Errorf("failed to unmarshal rapporteurs: %w", err)
	}

	return nil
}

func scanIntoCredential(rows *sql.Rows) (*domain.Credential, error) {
	credential := new(domain.Credential)
	err := rows.Scan(
		&credential.ID,
		&credential.HostID,
		&credential.Username,
		&credential.Password,
	)
	if err != nil {
		return nil, fmt.Errorf("error scanning Credential: %w", err)
	}

	return credential, nil
}

func replaceSQL(old, searchPattern string) string {
	tmpCount := strings.Count(old, searchPattern)
	for m := 1; m <= tmpCount; m++ {
		old = strings.Replace(old, searchPattern, "$"+strconv.Itoa(m), 1)
	}
	return old
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
	hostID int,
	timePeriodFilter string,
	severityFilters []string,
) ([]domain.ServiceTimePeriod, error) {
	// This query is kind of complicated, but what it does is fill out time_periods and labels,
	// even when there is no data for said time_period. E.g: we only have data
	// for February, but we want to have the counts for other months to be 0 too.
	baseTrendQuery := `
  		WITH TimePeriods as (
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
				END AS ordering_period
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
		VulnerabilityCounts AS (
			SELECT
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(s.started_at, 'FMMonth')
					WHEN $2 = 'Quarter' THEN 'Q' || TO_CHAR(s.started_at, 'Q')
					WHEN $2 = 'Semester' THEN 'Semester ' || CASE WHEN TO_CHAR(s.started_at, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE 'Unknown Period'
				END AS time_period_label,
				COUNT(sv.id) AS vulnerability_count
			FROM scan_vulnerabilities sv
			INNER JOIN scans s ON sv.scan_id = s.id
			WHERE s.host_id = $1 
				AND EXTRACT(YEAR FROM s.started_at) = EXTRACT(YEAR FROM CURRENT_DATE)
				-- Severity Filter Dynamic Condition goes here
				%s
			GROUP BY time_period_label
		)
		SELECT
			tp.time_period_label AS time_period,
			COALESCE(vc.vulnerability_count, 0) AS vulnerability_count
		FROM TimePeriods tp
		LEFT JOIN VulnerabilityCounts vc ON tp.time_period_label = vc.time_period_label
		ORDER BY tp.ordering_period;
  `

	trendQueryParams := []any{hostID, timePeriodFilter}
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

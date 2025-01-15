package storage

import (
	"database/sql"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) CreateScanTable() error {
	query := `create table if not exists scans (
      id SERIAL PRIMARY KEY,
      tenant_id UUID NOT NULL,
      operator_id UUID NOT NULL,
      status VARCHAR(50) NOT NULL, -- e.g., 'pending', 'in_progress', 'completed', 'failed'
      started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ended_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil

}

func (s *PostgreSQLStore) CreateScanHostsTable() error {
	query := `create table if not exists scan_hosts (
      id SERIAL PRIMARY KEY,
      scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      host_id INT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateScanResultsTable() error {
	query := `create table if not exists scans_results (
      id SERIAL PRIMARY KEY,
      scan_id INT REFERENCES scans (id) ON DELETE CASCADE,
      host_id INT REFERENCES hosts(id) ON DELETE CASCADE,
      tool_id INT REFERENCES tools(id) ON DELETE CASCADE,
      status  VARCHAR(50) NOT NULL,
      result JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateToolTable() error {
	query := `create table if not exists tools (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL, -- Tool name
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) ClearScanTable() error {
	query := `TRUNCATE TABLE scans RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateScan(sc *domain.Scan) (*domain.Scan, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction %w", err)
	}
	defer tx.Rollback()

	query := `
    INSERT INTO scans ( tenant_id, operator_id,status, started_at, ended_at)
    values ($1, $2,'', $3, $4)
    RETURNING id, tenant_id, operator_id, started_at, ended_at`

	row := tx.QueryRow(query, sc.TenantID, sc.OperatorID, sc.StartedAt, sc.EndedAt)
	newScan := &domain.Scan{}
	if err := scanIntoScan(row, newScan); err != nil {
		return nil, fmt.Errorf("failed to insert scan: %w", err)
	}
	sc.ID = newScan.ID
	errInsertScanHost := s.InsertScanHost(tx, sc)
	if errInsertScanHost != nil {
		return nil, errInsertScanHost
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return newScan, nil
}

func (s *PostgreSQLStore) InsertScanHost(tx *sql.Tx, sc *domain.Scan) error {
	query := `
    INSERT INTO scan_hosts (scan_id, host_id,status)
    values ($1, $2, $3)`

	if len(sc.HostIDs) == 0 {
		return fmt.Errorf("failed because no hostIDs were provided")
	}

	for _, hostID := range sc.HostIDs {
		if _, err := tx.Exec(query, sc.ID, hostID, 0); err != nil {
			return fmt.Errorf("failed to insert scan_hosts: %w", err)
		}
	}
	return nil
}

func scanIntoScan(row *sql.Row, scan *domain.Scan) error {
	if err := row.Scan(&scan.ID, &scan.TenantID, &scan.OperatorID, &scan.StartedAt, &scan.EndedAt); err != nil {
		return fmt.Errorf("error scanning row: %w", err)
	}
	return nil
}

func scanIntoScanSum(rows *sql.Rows) (*domain.ScanSummary, error) {
	scanSum := new(domain.ScanSummary)
	err := rows.Scan(
		&scanSum.ScanDate,
		&scanSum.Host,
		&scanSum.Vulnerability,
		&scanSum.Severity,
		&scanSum.Duration,
		&scanSum.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Scan: %w", err)
	}

	return scanSum, nil
}
func (s *PostgreSQLStore) GetScans(tenantID string) ([]*domain.ScanSummary, error) {

	query := `
    SELECT started_date, alias, vulnerability,severity, 
           EXTRACT(EPOCH FROM (started_at - ended_at)) as durations, status
    FROM scans
    INNER JOIN 
        scan_hosts SH ON scan_hosts.scan_id = scans.id
    INNER JOIN hosts H ON scan_hosts.host_id = H.id
    WHERE tenant_id=$1
  `

	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer rows.Close()

	scans := []*domain.ScanSummary{}
	for rows.Next() {
		scanSum, err := scanIntoScanSum(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		scans = append(scans, scanSum)
	}

	return scans, nil
}

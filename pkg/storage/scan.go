package storage

import (
	"database/sql"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) CreateScanTable() error {
	query := `create table if not exists scans (
      id SERIAL PRIMARY KEY,
      tenant_id UUID,
      operator_id UUID,
      started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ended_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil

}

func (s *PostgreSQLStore) CreateScanHostsTable() error {
	query := `create table if not exists scans_hosts (
      id SERIAL PRIMARY KEY,
      scan_id INT REFERENCES scans(id) ON DELETE CASCADE,
      host_id INT REFERENCES hosts(id) ON DELETE CASCADE,
      severity JSONB,
      vulnerability INT,
      ended_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      status decimal(3,2)
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
      scan_id integer REFERENCES scans (id) ON DELETE CASCADE,
      tool_name VARCHAR(255) NOT NULL,
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
    INSERT INTO scans ( tenant_id, operator_id, started_at, ended_at)
    values ($1, $2, $3, $4)
    RETURNING *`

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
    INSERT INTO scans_hosts (scan_id, host_id,status)
    values ($1, $2, $3)`

	for _, hostId := range sc.HostIDs {
		if _, err := tx.Exec(query, sc.ID, hostId, 0); err != nil {
			return fmt.Errorf("failed to insert credential: %w", err)
		}
	}
	return nil
}

func scanIntoScan(row *sql.Row, scan *domain.Scan) error {
	if err := row.Scan(&scan.ID, &scan.TenantID, &scan.OperatorID, &scan.StartedAt, &scan.EndedAt); err != nil {
		return fmt.Errorf("error scanning rows: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetScans() ([]*domain.Scan, error) {

	query := `
    SELECT *
    FROM scans
    WHERE tenant_id=$1 AND operator_id= $2
  `

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer rows.Close()

	scans := []*domain.Scan{}
	for rows.Next() {
		scan := &domain.Scan{}
		scans = append(scans, scan)
	}

	return scans, nil
}

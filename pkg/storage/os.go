package storage

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

var ErrOSNotFound = errors.New("operating system not found")

func (s *PostgreSQLStore) CreateOS(
	tx *sql.Tx,
	hostID int,
	scanID uuid.UUID,
	osData tools.OSData,
) error {
	query := `
    INSERT INTO operating_systems (
      host_id, scan_id, os_name, family, os_type, fingerprint, cpe, accuracy
  )
  VALUES ($1, $2, $3, $4, $5, $6, $7, $)
  `

	var execer interface {
		Exec(query string, args ...any) (sql.Result, error)
	}

	if tx != nil {
		execer = tx
	} else {
		execer = s.db
	}

	_, err := execer.Exec(
		query,
		hostID,
		scanID,
		osData.Name,
		osData.Family,
		osData.Type,
		osData.FingerPrint,
		osData.CPE,
		osData.Accuracy,
	)
	if err != nil {
		return fmt.Errorf("failed to insert service: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetOSByID(osID int) (*tools.OSData, error) {
	query := `
  SELECT os_name, family, os_type, fingerprint, cpe, accuracy 
  FROM operating_systems
  WHERE id = $1
  `

	var osData tools.OSData
	err := s.db.QueryRow(query, osID).Scan(
		&osData.Name,
		&osData.Family,
		&osData.Type,
		&osData.FingerPrint,
		&osData.CPE,
		&osData.Accuracy,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOSNotFound
		}
		return nil, fmt.Errorf("failed to query operating system: %w", err)
	}

	return &osData, nil
}

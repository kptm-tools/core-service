package storage

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
)

func (s *PostgreSQLStore) CreateOS(
	tx *sql.Tx,
	hostID int,
	scanID uuid.UUID,
	osData tools.OSData,
) (int, error) {
	query := `
    INSERT INTO operating_systems (
      host_id, scan_id, os_name, family, os_type, fingerprint, cpe, accuracy
  )
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
  RETURNING id
  `

	var querier interface {
		QueryRow(query string, args ...any) *sql.Row
	}

	if tx != nil {
		querier = tx
	} else {
		querier = s.db
	}

	var operatingSystemID int
	err := querier.QueryRow(
		query,
		hostID,
		scanID,
		osData.Name,
		osData.Family,
		osData.Type,
		osData.FingerPrint,
		osData.CPE,
		osData.Accuracy,
	).Scan(&operatingSystemID)
	if err != nil {
		return 0, fmt.Errorf("failed to insert operating system: %w", err)
	}
	return operatingSystemID, nil
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
			return nil, customerrors.ErrOSNotFound
		}
		return nil, fmt.Errorf("failed to query operating system: %w", err)
	}

	return &osData, nil
}

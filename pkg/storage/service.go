package storage

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

var ErrServiceNotFound = errors.New("service not found")

func (s *PostgreSQLStore) CreateService(
	tx *sql.Tx,
	hostID int,
	scanID uuid.UUID,
	portData tools.PortData,
) error {
	query := `
    INSERT INTO services (
      host_id, scan_id, port, protocol, sv_name, sv_version, confidence, cpe, product, port_state
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
    ON CONFLICT (host_id, port, protocol) DO NOTHING
    RETURNING id;
  `

	var serviceID int
	var err error
	var querier interface {
		QueryRow(query string, args ...any) *sql.Row
	}

	if tx != nil {
		querier = tx
	} else {
		querier = s.db
	}

	err = querier.QueryRow(
		query,
		hostID,
		scanID,
		portData.ID,
		portData.Protocol,
		portData.Service.Name,
		portData.Service.Version,
		portData.Service.Confidence,
		portData.Service.CPE,
		portData.Product,
		portData.State,
	).Scan(&serviceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// ON CONFLICT DO NOTHING happened, service already exists
			// Fetch the existing service ID
			existingServiceID, err := s.getServiceID(tx, hostID, portData.ID, portData.Protocol)
			if err != nil {
				return fmt.Errorf("failed to get existing service ID: %w", err)
			}
			serviceID = existingServiceID
		}
		return fmt.Errorf("failed to insert service: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) getServiceID(tx *sql.Tx, hostID int, port uint16, protocol string) (int, error) {
	query := `
    SELECT id
    FROM services
    WHERE host_id = $1 AND port = $2 AND protocol = $3
  `

	var serviceID int
	var err error
	var querier interface {
		QueryRow(query string, args ...any) *sql.Row
	}

	if tx != nil {
		querier = tx
	} else {
		querier = s.db
	}

	err = querier.QueryRow(query, hostID, port, protocol).Scan(&serviceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("service not found for host_id: %d, port: %d, protocol: %s: %w", hostID, port, protocol)
		}
		return 0, fmt.Errorf("failed to get service ID: %w", err)
	}
	return serviceID, nil
}

func (s *PostgreSQLStore) GetServiceByID(serviceID int) (*tools.PortData, error) {
	query := `
    SELECT port, protocol, sv_name, sv_version, confidence, cpe, product, port_state
    FROM services
    WHERE id = $1
  `

	var portData tools.PortData
	var service tools.Service

	err := s.db.QueryRow(
		query,
		serviceID,
	).Scan(
		&portData.ID,
		&portData.Protocol,
		&service.Name,
		&service.Version,
		&service.Confidence,
		&service.CPE,
		&portData.Product,
		&portData.State,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrServiceNotFound
		}
		return nil, fmt.Errorf("failed to query service: %w", err)
	}

	portData.Service = service

	return &portData, nil
}

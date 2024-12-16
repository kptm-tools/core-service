package storage

import (
	"database/sql"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) CreateHostsTable() error {
	query := `create table if not exists hosts (
      id SERIAL PRIMARY KEY,
      tenant_id UUID,
      operator_id UUID,
      value VARCHAR(2048) UNIQUE NOT NULL,
      type VARCHAR(10) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil

}

func (s *PostgreSQLStore) ClearHostsTable() error {
	query := `TRUNCATE TABLE hosts RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateHost(t *domain.Host) (*domain.Host, error) {

	query := `
    INSERT INTO hosts (tenant_id, operator_id, value, type,  created_at, updated_at)
    values ($1, $2, $3, $4, $5, $6)
    RETURNING id, tenant_id, operator_id, value, type, created_at, updated_at`

	rows, err := s.db.Query(query, t.TenantID, t.OperatorID, t.Value, t.Type, t.CreatedAt, t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("error creating Host: `%v`", err)
	}

	for rows.Next() {
		return scanIntoHost(rows)
	}

	return nil, fmt.Errorf("error creating Host")
}

func (s *PostgreSQLStore) GetHostsByTenantID(tenantID string) ([]*domain.Host, error) {

	query := `
    SELECT *
    FROM hosts
    WHERE tenant_id=$1
  `

	rows, err := s.db.Query(query, tenantID)

	if err != nil {
		return nil, fmt.Errorf("error fetching Hosts: `%+v`", err)
	}

	hosts := []*domain.Host{}

	for rows.Next() {
		host, err := scanIntoHost(rows)

		if err != nil {
			return nil, fmt.Errorf("error scanning into Host: `%+v`", err)
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func scanIntoHost(rows *sql.Rows) (*domain.Host, error) {

	host := new(domain.Host)

	err := rows.Scan(
		&host.ID,
		&host.TenantID,
		&host.OperatorID,
		&host.Value,
		&host.Type,
		&host.CreatedAt,
		&host.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return host, nil
}

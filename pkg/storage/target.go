package storage

import (
	"database/sql"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) CreateTargetsTable() error {
	query := `create table if not exists targets (
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

func (s *PostgreSQLStore) CreateTarget(t *domain.Target) (*domain.Target, error) {

	query := `
    INSERT INTO targets (tenant_id, operator_id, value, type,  created_at, updated_at)
    values ($1, $2, $3, $4, $5, $6)
    RETURNING id, tenant_id, operator_id, value, type, created_at, updated_at`

	rows, err := s.db.Query(query, t.TenantID, t.OperatorID, t.Value, t.Type, t.CreatedAt, t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("Error creating Target: `%v`", err)
	}

	for rows.Next() {
		return scanIntoTarget(rows)
	}

	return nil, fmt.Errorf("Error creating Target")
}

func (s *PostgreSQLStore) GetTargetsByTenantID(tenantID string) ([]*domain.Target, error) {

	query := `
    SELECT *
    FROM targets
    WHERE tenant_id=$1
  `

	rows, err := s.db.Query(query, tenantID)

	if err != nil {
		return nil, fmt.Errorf("Error fetching Targets: `%+v`", err)
	}

	targets := []*domain.Target{}

	for rows.Next() {
		target, err := scanIntoTarget(rows)

		if err != nil {
			return nil, fmt.Errorf("Error scanning into Target: `%+v`", err)
		}
		targets = append(targets, target)
	}

	return targets, nil
}

func scanIntoTarget(rows *sql.Rows) (*domain.Target, error) {

	target := new(domain.Target)

	err := rows.Scan(
		&target.ID,
		&target.TenantID,
		&target.OperatorID,
		&target.Value,
		&target.Type,
		&target.CreatedAt,
		&target.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return target, nil
}

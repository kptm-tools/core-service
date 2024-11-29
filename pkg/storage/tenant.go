package storage

import (
	"database/sql"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/domain"
)


func (s *PostgreSQLStore) CreateTenantsTable() error {
	query := `create table if not exists tenants (
      id SERIAL PRIMARY KEY,
      provider_id UUID,
      application_id UUID,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil

}

func (s *PostgreSQLStore) CreateTenant(t *domain.Tenant) (*domain.Tenant, error) {

	query := `
    INSERT INTO tenants (provider_id, application_id, created_at, updated_at)
    values ($1, $2, $3, $4)
    RETURNING id, provider_id, application_id, created_at, updated_at`

	rows, err := s.db.Query(query, t.ProviderID, t.ApplicationID, t.CreatedAt, t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("Error creating Tenant: `%v`", err)
	}

	for rows.Next() {
		return scanIntoTenant(rows)
	}

	return nil, fmt.Errorf("Error creating Tenant")
}


func scanIntoTenant(rows *sql.Rows) (*domain.Tenant, error) {

	tenant := new(domain.Tenant)

	err := rows.Scan(
		&tenant.ID,
		&tenant.ProviderID,
		&tenant.ApplicationID,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return tenant, nil
}
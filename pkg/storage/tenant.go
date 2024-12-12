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
	fmt.Println("Tenant table created")
	return nil

}

func (s *PostgreSQLStore) ClearTenantsTable() error {
	query := `TRUNCATE TABLE tenants RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) ExistsTenant(tenantID string) (bool, error) {

	var exists bool

	query := `
    SELECT EXISTS (
          SELECT FROM tenants
          WHERE provider_id=$1
    )
  `

	err := s.db.QueryRow(query, tenantID).Scan(&exists)

	if err != nil {
		return false, fmt.Errorf("Error checking tenant existence: `%+v`", err)
	}

	return exists, nil

}

func (s *PostgreSQLStore) CreateTenant(t *domain.Tenant) (*domain.Tenant, error) {
	exists, err := s.ExistsTenant(t.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("DB Error: %v", err)
	}

	if exists {
		return nil, fmt.Errorf("TenantID already exists: %s", t.ProviderID)
	}
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

func (s *PostgreSQLStore) GetTenants() ([]*domain.Tenant, error) {

	query := `
    SELECT *
    FROM tenants
  `

	rows, err := s.db.Query(query)

	if err != nil {
		return nil, fmt.Errorf("Error fetching Tenants: `%+v`", err)
	}

	tenants := []*domain.Tenant{}

	for rows.Next() {
		tenant, err := scanIntoTenant(rows)

		if err != nil {
			return nil, fmt.Errorf("Error scanning into Tenant: `%+v`", err)
		}
		tenants = append(tenants, tenant)
	}

	return tenants, nil
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

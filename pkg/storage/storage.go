package storage

import (
	"database/sql"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	_ "github.com/lib/pq"
)

type Storage interface {
	CreateTarget(*domain.Target) (*domain.Target, error)
	GetAllTargets(string) ([]*domain.Target, error)
}

type PostgreSQLStore struct {
	db *sql.DB
}

func NewPostgreSQLStore() (*PostgreSQLStore, error) {

	config := config.LoadConfig()

	connStr := config.PostgreSQLConnStr()
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		return nil, err
	}

	// Ping the DB to healthcheck it
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgreSQLStore{
		db: db,
	}, nil
}

func (s *PostgreSQLStore) Init() error {

	err := s.CreateTargetsTable()

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateTargetsTable() error {
	query := `create table if not exists gyms (
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
    INSERT INTO gyms (tenand_id, operator_id, value, type,  created_at, updated_at)
    values ($1, $2, $3, $4)
    RETURNING id, tenand_id, operator_id, value, type, created_at, updated_at`

	rows, err := s.db.Query(query, t.TenantID, t.OperatorID, t.Value, t.Type, t.CreatedAt, t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("Error creating Target: `%v`", err)
	}

	for rows.Next() {
		return scanIntoTarget(rows)
	}

	return nil, fmt.Errorf("Error creating Target")
}

func (s *PostgreSQLStore) GetAllTargets(tenantID string) ([]*domain.Target, error) {

	return nil, nil
}

func scanIntoTarget(rows *sql.Rows) (*domain.Target, error) {

	target := new(domain.Target)

	err := rows.Scan(
		&target.ID,
		&target.TenantID,
		&target.OperatorID,
		&target.CreatedAt,
		&target.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return target, nil
}

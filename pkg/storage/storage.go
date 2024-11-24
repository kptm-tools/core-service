package storage

import (
	"database/sql"

	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	_ "github.com/lib/pq"
)

type Storage interface {
	CreateTarget(*domain.Target) (*domain.Target, error)
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
      user_id UUID,
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

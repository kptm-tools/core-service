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

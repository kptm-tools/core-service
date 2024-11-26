package storage

import (
	"database/sql"
	"fmt"
	"regexp"

	"github.com/kptm-tools/core-service/pkg/config"
	_ "github.com/lib/pq"
)

type PostgreSQLStore struct {
	db *sql.DB
}

func NewPostgreSQLStore(connStr string) (*PostgreSQLStore, error) {

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
	dbName := config.LoadConfig().DatabaseName

	exists, err := s.dbExists(dbName)

	if err != nil {
		return err
	}

	if !exists {
		// Attempt to Create Core DB
		if err := s.CreateDB(dbName); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgreSQLStore) InitCoreDB() error {

	// Attempt to create Targets Table
	if err := s.CreateTargetsTable(); err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateDB(dbName string) error {

	if !isValidDatabaseName(dbName) {
		return fmt.Errorf("Invalid database name: `%s`", dbName)
	}

	query := fmt.Sprintf("CREATE DATABASE %s;", dbName)
	_, err := s.db.Exec(query)

	if err != nil {
		return fmt.Errorf("Error creating Database: `%+v`", err)
	}

	return nil

}

func (s *PostgreSQLStore) dbExists(dbName string) (bool, error) {

	var exists bool

	query := `
    SELECT EXISTS (
          SELECT FROM pg_database
          WHERE datname=$1
    )
  `

	err := s.db.QueryRow(query, dbName).Scan(&exists)

	if err != nil {
		return false, fmt.Errorf("Error checking database existence: `%+v`", err)
	}

	return exists, nil

}

func isValidDatabaseName(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_]{1,62}$`)
	return validName.MatchString(name)
}

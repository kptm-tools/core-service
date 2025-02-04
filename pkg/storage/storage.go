package storage

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/kptm-tools/core-service/pkg/config"
	_ "github.com/lib/pq"
)

type PostgreSQLStore struct {
	db         *sql.DB
	migrations fs.FS
}

func NewPostgreSQLStore(connStr string, migrations fs.FS) (*PostgreSQLStore, error) {

	db, err := sql.Open("postgres", connStr)

	if err != nil {
		return nil, err
	}

	db.SetMaxIdleConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxIdleTime(30 * time.Minute)

	// Ping the DB to healthcheck it
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &PostgreSQLStore{
		db:         db,
		migrations: migrations,
	}, nil
}

func (s *PostgreSQLStore) Init() error {
	cfg := config.LoadConfig()

	dbName := cfg.Database.Name
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

func (s *PostgreSQLStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *PostgreSQLStore) Migrate() error {
	cfg := config.LoadConfig()
	url := cfg.PostgreSQLDatabaseURL()

	slog.Debug("Running migrations")
	source, err := iofs.New(s.migrations, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create source: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, url)
	if err != nil {
		return fmt.Errorf("failed to initialize migrations: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	return nil
}

func (s *PostgreSQLStore) ClearCoreDB() error {
	if err := s.ClearScanVulnerabilitiesTable(); err != nil {
		return err
	}

	if err := s.ClearScanVulnerabilitiesTable(); err != nil {
		return err
	}

	// Attempt to clear Scans Table
	if err := s.ClearScanTable(); err != nil {
		return err
	}

	// Attempt to clear Hosts Table
	if err := s.ClearHostsTable(); err != nil {
		return err
	}
	// Attempt to clear Tenants Table
	if err := s.ClearTenantsTable(); err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateDB(dbName string) error {

	if !isValidDatabaseName(dbName) {
		return fmt.Errorf("invalid database name: `%s`", dbName)
	}

	query := fmt.Sprintf("CREATE DATABASE %s;", dbName)
	_, err := s.db.Exec(query)

	if err != nil {
		return fmt.Errorf("error creating Database: `%+v`", err)
	}

	return nil

}

func (s *PostgreSQLStore) Ping() error {
	return s.db.Ping()
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
		return false, fmt.Errorf("error checking database existence: `%+v`", err)
	}

	return exists, nil

}

func isValidDatabaseName(name string) bool {
	validName := regexp.MustCompile(`^[a-zA-Z0-9_]{1,62}$`)
	return validName.MatchString(name)
}

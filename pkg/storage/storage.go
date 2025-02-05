package storage

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
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
	config     *config.Config
}

func NewPostgreSQLStore(cfg *config.Config, migrations fs.FS) (*PostgreSQLStore, error) {

	if err := createDatabaseIfNotExists(cfg); err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	db, err := sql.Open("postgres", cfg.PostgreSQLCoreDatabaseURL())

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
		config:     cfg,
	}, nil
}

// createDatabaseIfNotExists handles database creation before main connection
func createDatabaseIfNotExists(cfg *config.Config) error {
	defaultConnStr := cfg.PostgreSQLDefaultDatabaseURL()

	db, err := sql.Open("postgres", defaultConnStr)
	if err != nil {
		return fmt.Errorf("failed to connect to default database: %w", err)
	}
	defer db.Close()

	dbName := cfg.Database.Name
	query := `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)`
	var exists bool
	err = db.QueryRow(query, dbName).Scan(&exists)

	// If the database doesn't exist, create it
	if err != nil {
		return fmt.Errorf("failed to check databse existence: %w", err)
	}

	if !exists {
		createQuery := fmt.Sprintf("CREATE DATABASE %s", dbName)
		_, err = db.Exec(createQuery)
		if err != nil {
			return fmt.Errorf("failed to create database %s: %w", dbName, err)
		}
		slog.Info("Database created successfully", slog.String("name", dbName))

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
	url := cfg.PostgreSQLCoreDatabaseURL()

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
		return fmt.Errorf("failed to apply up migrations: %w", err)
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

func (s *PostgreSQLStore) Ping() error {
	return s.db.Ping()
}

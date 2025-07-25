package storage

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	_ "github.com/lib/pq"
)

type PostgreSQLStore struct {
	db      *sql.DB
	queries *repository.Queries

	Host          interfaces.HostRepository
	Scan          interfaces.ScanRepository
	ScanSchedule  interfaces.ScanScheduleRepository
	ScanResult    interfaces.ScanResultRepository
	OS            interfaces.OSRepository
	Service       interfaces.ServiceRepository
	Vulnerability interfaces.VulnerabilityRepository
	Cve           interfaces.CVERepository
	Cwe           interfaces.CWERepository
	migrations    fs.FS
	config        *config.Config
}

func NewPostgreSQLStore(cfg *config.Config, migrations fs.FS) (*PostgreSQLStore, error) {
	sqlDB, err := sql.Open("postgres", cfg.PostgreSQLCoreDatabaseURL())
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxIdleTime(30 * time.Minute)

	// Ping the DB to healthcheck it
	if err := sqlDB.Ping(); err != nil {
		return nil, err
	}

	// Create the sqlc Queries instance
	queries := repository.New(sqlDB)

	return &PostgreSQLStore{
		db:      sqlDB,
		queries: queries,

		Host:          NewHostRepository(queries),
		Scan:          NewScanRepository(queries),
		ScanSchedule:  NewScanScheduleRepository(queries),
		OS:            NewOSRepository(queries),
		Service:       NewServiceRepository(queries),
		Vulnerability: NewVulnerRepository(queries, sqlDB),
		ScanResult:    NewScanResultRepository(queries),
		Cve:           NewCVERepository(queries),
		Cwe:           NewCWERepository(queries),
		migrations:    migrations,
		config:        cfg,
	}, nil
}

func (s *PostgreSQLStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// migrator initializes and returns a *migrate.Migrate instance.
func (s *PostgreSQLStore) migrator() (*migrate.Migrate, error) {
	source, err := iofs.New(s.migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to create source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, s.config.PostgreSQLCoreDatabaseURL())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize migration: %w", err)
	}
	return m, nil
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

// Up applies all up migrations.
func (s *PostgreSQLStore) Up() error {
	slog.Debug("Running Up migrations")
	m, err := s.migrator()
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("Up migration failed: %w", err)
	}
	return nil
}

// RollBack rolls back the most recent migration.
func (s *PostgreSQLStore) RollBack() error {
	slog.Debug("Running RollBack migration")
	m, err := s.migrator()
	if err != nil {
		return err
	}
	// Steps(-1) rolls back one migration
	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("RollBack migration failed: %w", err)
	}
	return nil
}

// Drop drops all database objects (brings version to zero).
func (s *PostgreSQLStore) Drop() error {
	slog.Debug("Running Drop migrations")
	m, err := s.migrator()
	if err != nil {
		return err
	}
	if err := m.Drop(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("Drop migration failed: %w", err)
	}
	return nil
}

// Down drops all database objects (brings version to zero).
func (s *PostgreSQLStore) Down() error {
	slog.Debug("Running Down migrations")
	m, err := s.migrator()
	if err != nil {
		return err
	}
	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("Down migration failed: %w", err)
	}
	return nil
}

// Force sets the migration version without running migrations.
func (s *PostgreSQLStore) Force(version int) error {
	slog.Debug("Forcing migration version", "version", version)
	m, err := s.migrator()
	if err != nil {
		return err
	}
	if err := m.Force(version); err != nil {
		return fmt.Errorf("Force migration failed: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) Ping() error {
	return s.db.Ping()
}

// DoInTX implements interfaces.TxManager
// It executes the given function 'fn' inside a transaction.
func (s *PostgreSQLStore) DoInTX(ctx context.Context, fn interfaces.TxFunc) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	qtx := s.queries.WithTx(tx)

	// Store the transactional queries in the context, to allow repositories to
	// retrieve them without directly exposing the *sql.Tx
	ctx = context.WithValue(ctx, txKey, qtx)
	err = fn(ctx)
	if err != nil {
		return fmt.Errorf("transaction failed: %w", err)
	}

	// Commit on success
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// A private context key to store the *db.Queries instance backed by a transaction
type contextKey string

const txKey contextKey = "txQueries"

// GetQueriesFromContext retrieves the *repository.Queries instance from the context.
// It will be the transactional instance if DoInTx was used, or the default non-transactional instance otherwise.
// This is an internal helper for repositories.
func GetQueriesFromContext(ctx context.Context, defaultQueries *repository.Queries) *repository.Queries {
	if q, ok := ctx.Value(txKey).(*repository.Queries); ok {
		return q
	}
	return defaultQueries
}

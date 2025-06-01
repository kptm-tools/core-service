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
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
	_ "github.com/lib/pq"
)

type PostgreSQLStore struct {
	db      *sql.DB
	queries *repository.Queries

	Host          interfaces.HostRepository
	Scan          interfaces.ScanRepository
	OS            interfaces.OSRepository
	Service       interfaces.ServiceRepository
	Vulnerability interfaces.VulnerabilityRepository

	migrations fs.FS
	config     *config.Config
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
		OS:            NewOSRepository(queries),
		Service:       NewServiceRepository(queries),
		Vulnerability: NewVulnerRepo(queries),
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
	// Attempt to clear Scans Table
	if err := s.ClearScanTable(); err != nil {
		return err
	}
	// Attempt to clear Scan Results Table
	if err := s.ClearScanResultsTable(); err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) Ping() error {
	return s.db.Ping()
}

func (s *PostgreSQLStore) GetDB() *sql.DB {
	return s.db
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

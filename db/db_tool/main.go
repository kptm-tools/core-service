package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	repository "github.com/kptm-tools/core-service/db"
	migrations "github.com/kptm-tools/core-service/db/sql"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
	"github.com/kptm-tools/core-service/pkg/utils"
	_ "github.com/lib/pq"
	"github.com/lmittmann/tint"
)

// Global variables
var (
	coreStore      *storage.PostgreSQLStore
	logger         *slog.Logger
	db             *sql.DB
	migrationsPath = "./cmd/migrations/migrations"
)

func init() {
	// Initialize logger first (do not shadow the global)
	logger = slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: time.Stamp,
	}))
	slog.SetDefault(logger)

	// Load config
	cfg := config.LoadConfig()

	// Initialize database store (migrations)
	var err error
	coreStore, err = storage.NewPostgreSQLStore(cfg, migrations.Migrations)
	if err != nil {
		logger.Error("Failed to create Core DB store", slog.Any("error", err))
		os.Exit(1)
	}

	// Also open a direct DB connection for custom commands
	db, err = sql.Open("postgres", cfg.PostgreSQLCoreDatabaseURL())
	if err != nil {
		logger.Error("Failed to open DB connection", slog.Any("error", err))
		os.Exit(1)
	}

	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(5)
	db.SetConnMaxIdleTime(30 * time.Minute)

	// Ping the DB to healthcheck it
	if err := db.Ping(); err != nil {
		logger.Error("Failed to ping DB", slog.Any("error", err))
		os.Exit(1)
	}
}

func main() {
	defer coreStore.Close()
	defer db.Close()

	args := os.Args[1:]
	if len(args) < 1 {
		printHelp()
		return
	}

	command := args[0]

	switch command {
	case "up":
		runMigrationsUp()
	case "down":
		runMigrationsDown()
	case "rollback":
		runMigrationsRollback()
	case "drop":
		runMigrationsDrop()
		resetPublicSchema()
	case "force":
		if len(args) < 2 {
			logger.Error("Missing version number. Usage: go run main.go force <version>")
			os.Exit(1)
		}
		version, err := strconv.Atoi(args[1])
		if err != nil {
			logger.Error("Invalid version format. Must be an integer.", slog.Any("error", err))
			os.Exit(1)
		}
		runMigrationsForce(version)
	case "gen":
		generateSQLC()
	case "create":
		createMigration()
	case "populate-cwe":
		populateCWE()
	default:
		printHelp()
	}
}

func runMigrationsUp() {
	if err := coreStore.Up(); err != nil {
		logger.Error("Error running migrations up", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Up migrations ran successfully")
}

func runMigrationsDown() {
	if err := coreStore.Down(); err != nil {
		logger.Error("Error running migrations down", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Down migrations ran successfully")
}

func runMigrationsForce(version int) {
	if err := coreStore.Force(version); err != nil {
		logger.Error("Error forcing migration version", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Migrations version forced successfully", "version", version)
}

func runMigrationsRollback() {
	if err := coreStore.RollBack(); err != nil {
		logger.Error("Error rolling back migrations", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Migrations rolled back successfully")
}

func runMigrationsDrop() {
	if err := coreStore.Drop(); err != nil {
		logger.Error("Error dropping database schema", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("Database schema dropped successfully")
}

// dropEnums drops all configured ENUM types from the database
func resetPublicSchema() {
	statements := []string{
		"DROP SCHEMA public CASCADE;",
		"CREATE SCHEMA public;",
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			logger.Error("Error executing statement", slog.String("stmt", stmt), slog.Any("error", err))
			os.Exit(1)
		}
		logger.Info("Executed statement", slog.String("stmt", stmt))
	}
}

func generateSQLC() {
	dir := "db/sql"
	if err := os.Chdir(dir); err != nil {
		logger.Error("Failed to change directory", slog.String("dir", dir), slog.Any("error", err))
		os.Exit(1)
	}

	cmd := exec.Command("sqlc", "generate")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	logger.Info("Generating SQL code with sqlc...")

	if err := cmd.Run(); err != nil {
		logger.Error("Error running sqlc generate", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("SQL code generation completed successfully")
}

func createMigration() {
	if len(os.Args) < 3 {
		logger.Error("Missing migration name. Usage: go run main.go create <migration_name>")
		os.Exit(1)
	}

	name := os.Args[2]

	cmd := exec.Command("migrate", "create", "-ext", "sql", "-dir", migrationsPath, "-seq", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	logger.Info("Creating migration", slog.String("name", name))

	if err := cmd.Run(); err != nil {
		logger.Error("Error creating migration", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Migration created successfully", slog.String("name", name))
}

func populateCWE() {
	ctx := context.Background()

	logger.Info("Starting CWE population process...")

	// Find project root first
	projectRoot, err := utils.FindProjectRoot()
	if err != nil {
		logger.Warn("Could not determine project root, using relative paths", slog.Any("error", err))
		projectRoot = "."
	}

	// Construct path to CWE JSON file
	cweFilePath := filepath.Join(projectRoot, "data", "cwe.json")

	// Check if file exists
	if _, err := os.Stat(cweFilePath); os.IsNotExist(err) {
		// Try current working directory as fallback
		cweFilePath = "data/cwe.json"
		if _, err := os.Stat(cweFilePath); os.IsNotExist(err) {
			logger.Error("CWE JSON file not found",
				slog.String("expected_path", filepath.Join(projectRoot, "data", "cwe.json")),
				slog.String("fallback_path", "data/cwe.json"))
			os.Exit(1)
		}
	}

	logger.Info("Found CWE JSON file", slog.String("path", cweFilePath))

	// Initialize CWE parser
	parser := services.NewCWEParser()

	// Load and parse CWE data
	cweData, err := parser.LoadCWE(cweFilePath)
	if err != nil {
		logger.Error("Failed to load and parse CWE data", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("Successfully parsed CWE data", slog.Int("weakness_count", len(cweData)))

	// Create queries instance for database operations
	queries := repository.New(db)

	var successCount, errorCount int

	// First, insert the special edge case CWE records
	logger.Info("Inserting special CWE records for edge cases...")

	specialCWEs := []struct {
		ID                 string
		Name               string
		Description        string
		OwaspTop10Category string
	}{
		{
			ID:                 "CWE-Other",
			Name:               "Other or Uncategorized Weakness",
			Description:        "This vulnerability falls into a category that is not otherwise classified. Further manual analysis is recommended.",
			OwaspTop10Category: enums.OwaspCategoryOther.String(),
		},
		{
			ID:                 "CWE-noinfo",
			Name:               "No Information Available",
			Description:        "The scanning tool did not provide a specific weakness classification for this finding.",
			OwaspTop10Category: enums.OwaspCategoryNoInfo.String(),
		},
	}

	for _, special := range specialCWEs {
		_, err := queries.CreateOrUpdateCWEDetail(ctx, repository.CreateOrUpdateCWEDetailParams{
			CweID:              special.ID,
			Title:              special.Name,
			Description:        special.Description,
			LastUpdated:        time.Now().UTC(),
			OwaspTop10Category: sql.NullString{String: special.OwaspTop10Category, Valid: true},
		})
		if err != nil {
			logger.Error("Failed to insert special CWE record",
				slog.String("cwe_id", special.ID),
				slog.Any("error", err))
			errorCount++
		} else {
			logger.Info("Created special CWE record", slog.String("cwe_id", special.ID))
			successCount++
		}
	}

	// Insert/update each CWE weakness from the JSON data
	for cweID, weakness := range cweData {
		// Insert/update the main CWE detail
		_, err := queries.CreateOrUpdateCWEDetail(ctx, repository.CreateOrUpdateCWEDetailParams{
			CweID:              cweID,
			Title:              weakness.Name,
			Description:        weakness.Description,
			LastUpdated:        weakness.LastUpdated,
			OwaspTop10Category: sql.NullString{String: weakness.OwaspTop10Category, Valid: weakness.OwaspTop10Category != ""},
		})
		if err != nil {
			logger.Error("Failed to insert/update CWE detail",
				slog.String("cwe_id", cweID),
				slog.Any("error", err))
			errorCount++
			continue
		}

		// Insert each mitigation for this CWE
		for _, mitigation := range weakness.Mitigations {
			_, err := queries.CreateCWERemediation(ctx, repository.CreateCWERemediationParams{
				CweID:              cweID,
				MitigationID:       sql.NullString{String: mitigation.MitigationID, Valid: mitigation.MitigationID != ""},
				Phase:              mitigation.Phase,
				Description:        mitigation.Description,
				Effectiveness:      sql.NullString{String: mitigation.Effectiveness, Valid: mitigation.Effectiveness != ""},
				EffectivenessNotes: sql.NullString{String: mitigation.EffectivenessNotes, Valid: mitigation.EffectivenessNotes != ""},
				CreatedAt:          sql.NullTime{Time: time.Now(), Valid: true},
			})
			if err != nil {
				logger.Error("Failed to insert CWE mitigation",
					slog.String("cwe_id", cweID),
					slog.String("mitigation_id", mitigation.MitigationID),
					slog.Any("error", err))
				errorCount++
				continue
			}
		}

		successCount++
		if successCount%100 == 0 {
			logger.Info("Progress update", slog.Int("processed", successCount))
		}
	}

	logger.Info("CWE population completed",
		slog.Int("success_count", successCount),
		slog.Int("error_count", errorCount))

	if errorCount > 0 {
		logger.Warn("Some errors occurred during population", slog.Int("error_count", errorCount))
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("Usage: go run main.go <command>")
	fmt.Println("Available commands:")
	fmt.Println("  create <name>   - Create a new migration file")
	fmt.Println("  up              - Run database migrations up")
	fmt.Println("  down            - Revert the latest migration")
	fmt.Println("  rollback        - Rollback one step of migrations")
	fmt.Println("  drop            - Drop all migration tables and enum types")
	fmt.Println("  force <version> - Force migration to a specific version")
	fmt.Println("  gen             - Run sqlc code generation")
	fmt.Println("  populate-cwe    - Populate CWE details and mitigations from data/cwe.json")
}

package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"time"

	migrations "github.com/kptm-tools/core-service/db/sql"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/storage"
	"github.com/lmittmann/tint"
)

// Global variables
var (
	coreStore      *storage.PostgreSQLStore
	logger         *slog.Logger
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
	c := config.LoadConfig()

	// Initialize database
	var err error
	coreStore, err = storage.NewPostgreSQLStore(c, migrations.Migrations)
	if err != nil {
		logger.Error("Failed to create Core DB store", slog.Any("error", err))
		os.Exit(1)
	}
}

func main() {
	defer coreStore.Close()

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
	default:
		printHelp()
	}
}

func runMigrationsUp() {
	if err := coreStore.Up(); err != nil {
		logger.Error("Error running migrations", slog.Any("error", err))
		os.Exit(1)
	}
}

func runMigrationsDown() {
	if err := coreStore.Down(); err != nil {
		logger.Error("Error running down migrations", slog.Any("error", err))
		os.Exit(1)
	}
}

func runMigrationsForce(version int) {
	if err := coreStore.Force(version); err != nil {
		logger.Error("Error forcing migration version", slog.Any("error", err))
		os.Exit(1)
	}
}

func runMigrationsRollback() {
	if err := coreStore.RollBack(); err != nil {
		logger.Error("Error rolling back migrations", slog.Any("error", err))
		os.Exit(1)
	}
}

func runMigrationsDrop() {
	if err := coreStore.Drop(); err != nil {
		logger.Error("Error dropping database schema", slog.Any("error", err))
		os.Exit(1)
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

func printHelp() {
	fmt.Println("Usage: go run main.go <command>")
	fmt.Println("Available commands:")
	fmt.Println("  create <name>   - Create a new migration file")
	fmt.Println("  up              - Run database migrations up")
	fmt.Println("  down            - Revert the latest migration")
	fmt.Println("  rollback        - Rollback one step of migrations")
	fmt.Println("  drop            - Drop all migration tables")
	fmt.Println("  force <version> - Force migration to a specific version")
	fmt.Println("  gen             - Run sqlc code generation")
}

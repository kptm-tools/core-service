package main

import (
	"log/slog"
	"os"
	"time"

	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/cmd/migrations"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/events"
	"github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
	"github.com/lmittmann/tint"
)

func main() {
	c := config.LoadConfig()

	// Configure logging
	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level:      slog.LevelDebug,
		TimeFormat: time.Stamp,
	}))
	slog.SetDefault(logger)

	coreStore, err := storage.NewPostgreSQLStore(c, migrations.Migrations)
	if err != nil {
		logger.Error("Failed to create Core DB store", slog.Any("error", err))
		os.Exit(1)
	}
	defer coreStore.Close()

	if err := coreStore.Migrate(); err != nil {
		logger.Error("Error running migrations", slog.Any("error", err))
		os.Exit(1)
	}

	eventBus, err := cmmn.NewNatsEventBus(c.GetNatsConnStr())
	if err != nil {
		logger.Error("Error creating Event Bus", slog.Any("error", err))
		os.Exit(1)
	}
	defer eventBus.Close()

	// Services
	healthService := services.NewHealthcheckService(c, coreStore)
	authService := services.NewAuthService(coreStore)
	hostService := services.NewHostService(coreStore)
	tenantService := services.NewTenantService(coreStore)
	scanService := services.NewScanService(coreStore)
	vulnService := services.NewVulnerabilityService(coreStore)
	scanScheduleService := services.NewScanScheduleService(coreStore)
	emailService := services.NewEmailService(
		c.SMTP.Host,
		c.SMTP.Port,
		c.SMTP.Username,
		c.SMTP.Password,
		c.SMTP.FromEmail)

	// Handlers
	healthHandler := handlers.NewHealthcheckHandlers(healthService)
	authHandlers := handlers.NewAuthHandlers(authService)
	hostHandlers := handlers.NewHostHandlers(hostService)
	tenantHandlers := handlers.NewTenantHandlers(tenantService)
	scanHandlers := handlers.NewScanHandlers(
		scanService,
		scanScheduleService,
		hostService,
		emailService,
		eventBus)
	vulnHandlers := handlers.NewVulnerabilityHandlers(vulnService)
	scanScheduleHandlers := handlers.NewScanScheduleHandlers(scanScheduleService)
	wsServer := handlers.NewWsHandlers()

	// Event Subscriptions
	if err := events.SetupEventBus(eventBus, scanService); err != nil {
		slog.Error("Failed to set up Event Bus", slog.Any("error", err))
	}

	storageListener, err := storage.NewPostgresListener(c, scanService, emailService, eventBus)
	if err != nil {
		logger.Error("Error creating db listener", slog.Any("error", err))
		os.Exit(1)
	}
	defer storageListener.Close()

	// Server
	s := api.NewAPIServer(
		":8000",
		healthHandler,
		hostHandlers,
		tenantHandlers,
		authHandlers,
		scanHandlers,
		vulnHandlers,
		scanScheduleHandlers,
		wsServer,
	)

	if err := s.Init(); err != nil {
		slog.Error("Failed to initialize APIServer", slog.Any("error", err))
	}
}

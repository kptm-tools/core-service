package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/report"
	"github.com/kptm-tools/core-service/pkg/ws/scan"

	cmmn "github.com/kptm-tools/common/common/pkg/events"
	migrations "github.com/kptm-tools/core-service/db/sql"
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

	eventBus, err := cmmn.NewNatsEventBus(c.GetNatsConnStr())
	if err != nil {
		logger.Error("Error creating Event Bus", slog.Any("error", err))
		os.Exit(1)
	}
	defer eventBus.Close()

	// Services
	healthService := services.NewHealthcheckService(c, coreStore)
	authService := services.NewAuthService()
	hostService := services.NewHostService(coreStore.Host)
	dashboardService := services.NewDashboardService(coreStore.Vulnerability, coreStore.Scan, coreStore.Host)
	scanService := services.NewScanService(coreStore.Vulnerability, coreStore.Scan, coreStore.Host, coreStore.ScanResult)
	vulnService := services.NewVulnerabilityService(coreStore, coreStore.OS, coreStore.Service, coreStore.Vulnerability, coreStore.Scan, coreStore.Host, coreStore.Cve, coreStore.Cwe)
	scanScheduleService := services.NewScanScheduleService(coreStore, coreStore.Scan, coreStore.ScanSchedule)
	emailService := services.NewEmailService(
		c.SMTP.Host,
		c.SMTP.Port,
		c.SMTP.Username,
		c.SMTP.Password,
		c.SMTP.FromEmail)

	// Handlers - REST
	healthHandler := handlers.NewHealthcheckHandlers(healthService)
	authHandlers := handlers.NewAuthHandlers(authService)
	hostHandlers := handlers.NewHostHandlers(hostService)
	dashboardHandlers := handlers.NewDashboardHandlers(dashboardService)
	scanHandlers := handlers.NewScanHandlers(
		scanService,
		vulnService,
		scanScheduleService,
		hostService,
		emailService,
		eventBus)
	vulnHandlers := handlers.NewVulnerabilityHandlers(vulnService)
	scanScheduleHandlers := handlers.NewScanScheduleHandlers(scanScheduleService)

	// Handlers - WS
	wsConfig := &common.Config{
		Upgrader: websocket.Upgrader{
			CheckOrigin:     authService.CheckOriginAllowed,
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		PongWait:     10 * time.Second,
		PingInterval: (10 * time.Second * 9) / 10,
	}

	scanHub := scan.NewScanHub(wsConfig, scanService, authService, 5)
	reportHub := report.NewReportHub(wsConfig, scanService, authService)

	// Event Subscriptions
	if err := events.SetupEventBus(c, eventBus, scanService, vulnService); err != nil {
		slog.Error("Failed to set up Event Bus", slog.Any("error", err))
	}

	storageListener, err := storage.NewPostgresListener(c, scanService, scanScheduleService, emailService, eventBus)
	if err != nil {
		logger.Error("Error creating db listener", slog.Any("error", err))
		os.Exit(1)
	}
	defer storageListener.Close()

	// Server
	s := api.NewAPIServer(
		":"+c.Server.Port,
		healthHandler,
		hostHandlers,
		dashboardHandlers,
		authHandlers,
		scanHandlers,
		vulnHandlers,
		scanScheduleHandlers,
		scanHub,
		reportHub,
	)

	apiSrv := s.Init()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)

	// Start API Server
	go func() {
		if err := apiSrv.ListenAndServe(); err != nil {
			slog.Error("Failed to initialize APIServer", slog.Any("error", err))
		}
	}()

	// Wait for the interrupt signal to gracefully shutdown
	sig := <-sigs
	slog.Info("Received signal to shutdown", slog.Any("signal", sig))

	// Create deadline for the shutdown
	ctxDeadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := apiSrv.Shutdown(ctxDeadline); err != nil {
		slog.Error("Error shutting down API Server", slog.Any("error", err))
	}
}

package main

import (
	"log"

	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
)

func main() {
	c := config.LoadConfig()

	rootStore, err := storage.NewPostgreSQLStore(c.PostgreSQLRootConnStr())

	if err != nil {
		log.Fatal("Failed to create DB store ", err.Error())
	}

	if err := rootStore.Init(); err != nil {
		log.Fatalf("Error initializing DB: `%+v`", err)
	}

	coreStore, err := storage.NewPostgreSQLStore(c.PostgreSQLCoreConnStr())

	if err != nil {
		log.Fatalf("Failed to create Core DB store: `%+v`", err)
	}

	if err := coreStore.InitCoreDB(); err != nil {
		log.Fatalf("Error initializing Core DB: `%+v`", err)
	}

	eventBus, err := cmmn.NewNatsEventBus(c.GetNatsConnStr())
	if err != nil {
		log.Fatalf("Error creating Event Bus: %s", err.Error())
	}

	// Services
	healthService := services.NewHealthcheckService(coreStore)
	authService := services.NewAuthService(coreStore)
	hostService := services.NewHostService(coreStore)
	tenantService := services.NewTenantService(coreStore)
	scanService := services.NewScanService(coreStore)

	// Handlers
	healthHandler := handlers.NewHealthcheckHandlers(healthService)
	authHandlers := handlers.NewAuthHandlers(authService)
	hostHandlers := handlers.NewHostHandlers(hostService)
	tenantHandlers := handlers.NewTenantHandlers(tenantService)
	scanHandlers := handlers.NewScanHandlers(scanService, eventBus)
	// Server
	s := api.NewAPIServer(":8000", healthHandler, hostHandlers, tenantHandlers, authHandlers, scanHandlers)

	if err := s.Init(); err != nil {
		log.Fatalf("Failed to initialize APIServer: `%+v`", err)
	}

}

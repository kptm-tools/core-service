package main

import (
	"fmt"
	"log"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
	"github.com/kptm-tools/core-service/pkg/utils"
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

	// Services
	authService := services.NewAuthService()
	targetService := services.NewTargetService(coreStore)
	tenantService := services.NewTenantService(coreStore)

	// Handlers
	authHandlers := handlers.NewAuthHandlers(authService)
	targetHandlers := handlers.NewTargetHandlers(targetService)
	result, err := utils.OpenAndReadKickstartJson(tenantService)
	fmt.Println(result)

	// Server
	s := api.NewAPIServer(":8000", targetHandlers, authHandlers)

	if err := s.Init(); err != nil {
		log.Fatalf("Failed to initialize APIServer: `%+v`", err)
	}

}

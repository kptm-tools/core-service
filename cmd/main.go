package main

import (
	"log"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
)

func main() {

	store, err := storage.NewPostgreSQLStore()

	if err != nil {
		log.Fatal("Failed to create DB store ", err.Error())
	}

	if err := store.Init(); err != nil {
		log.Fatalf("Error initializing DB: `%+v`", err)
	}

	// Services
	targetService := services.NewTargetService()

	// Handlers
	targetHandlers := handlers.NewTargetHandlers(targetService)

	// Server
	s := api.NewAPIServer(":8000", targetHandlers)

	if err := s.Init(); err != nil {
		log.Fatalf("Failed to initialize APIServer: `%+v`", err)
	}

}

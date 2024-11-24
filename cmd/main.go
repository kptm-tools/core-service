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

	log.Printf("Created DB store successfully: `%+v`", store)

	// Services
	targetService := services.NewTargetService()

	// Handlers
	targetHandlers := handlers.NewTargetHandlers(targetService)

	// Server
	s := api.NewAPIServer(":8000", targetHandlers)

	err := s.Init()

}

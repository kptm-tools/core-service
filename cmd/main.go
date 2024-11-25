package main

import (
	"log"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/services"
)

func main() {

	// Services
	targetService := services.NewTargetService()

	// Handlers
	targetHandlers := handlers.NewTargetHandlers(targetService)

	// Server
	s := api.NewAPIServer(":8000", targetHandlers)

	err := s.Init()

	if err != nil {
		log.Fatalf("Error initializing APIServer: `%v`", err)
	}

}

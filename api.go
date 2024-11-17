package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
)

type APIServer struct {
	listenAddr string
}

func NewAPIServer(listenAddr string) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
	}
}

func (s *APIServer) Init() error {
	app := fiber.New()
	v1 := app.Group("/v1")

	log.Println("Server listening on port: ", s.listenAddr)

	// server.ListenAndServe()
	rootRoutes := v1.Group("/")
	rootRoutes.Get("/healthcheck", HandleHealthCheck)

	return app.Listen(s.listenAddr)

}

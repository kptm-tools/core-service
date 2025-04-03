package report

import (
	"log/slog"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/ws/common"
	wshandlers "github.com/kptm-tools/core-service/pkg/ws/report/handlers"
)

type ReportHub struct {
	cfg        *common.Config
	clients    map[string]common.IClient
	register   chan common.IClient
	unregister chan common.IClient
	handlers   map[string]common.IHandler
}

var _ common.IHub = (*ReportHub)(nil)

func NewReportHub(config *common.Config, initialRequestHandler, vectorUpdateHandler common.IHandler) *ReportHub {
	handlers := map[string]common.IHandler{
		wshandlers.MessageInitialRequest: initialRequestHandler,
		wshandlers.MessageVectorUpdate:   vectorUpdateHandler,
	}

	return &ReportHub{
		cfg:        config,
		clients:    make(map[string]common.IClient),
		register:   make(chan common.IClient),
		unregister: make(chan common.IClient),
		handlers:   handlers,
	}
}

func (h *ReportHub) Serve(w http.ResponseWriter, r *http.Request) {
	conn, err := h.cfg.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	// Create a new client
	client := NewReportClient(h.cfg, conn, h)
	// Register the new client to the hub
	h.Register(client)

	go client.WriteMessages()
	go client.ReadMessages()
}

// Run spins up the select statement for managing clients concurrently.
func (h *ReportHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client.GetID()] = client
		case client := <-h.unregister:
			if client, ok := h.clients[client.GetID()]; ok {
				slog.Info("Client unregistered", slog.String("client_id", client.GetID()))
				if err := client.Close(); err != nil {
					slog.Error("Failed to close client",
						slog.String("client_id", client.GetID()),
						slog.Any("error", err))
				}
				delete(h.clients, client.GetID())
			}
		}
	}
}

// Register will add clients to our clientList
func (h *ReportHub) Register(client common.IClient) {
	// Add Client
	h.register <- client
}

// Unregister will remove clients from the clientList
func (h *ReportHub) Unregister(client common.IClient) {
	h.unregister <- client
}

func (h *ReportHub) routeMessage(msg common.Message, client *ReportClient) error {
	handler, ok := h.handlers[msg.Type]
	if !ok {
		return common.ErrMessageNotSupported
	}

	if err := handler.Handle(msg, client); err != nil {
		return err
	}

	return nil
}

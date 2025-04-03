package scan

import (
	"log/slog"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/utils"
)

type ScanHub struct {
	cfg         *common.Config
	clients     map[string]common.IClient
	broadcast   chan []byte
	register    chan common.IClient
	unregister  chan common.IClient
	scanService interfaces.IScanService
}

var _ common.IHub = (*ScanHub)(nil)

func NewScanHub(config *common.Config, scanService interfaces.IScanService) *ScanHub {
	server := &ScanHub{
		cfg:         config,
		clients:     make(map[string]common.IClient),
		broadcast:   make(chan []byte),
		register:    make(chan common.IClient),
		unregister:  make(chan common.IClient),
		scanService: scanService,
	}
	return server
}

func (h *ScanHub) Serve(w http.ResponseWriter, r *http.Request) {
	tenantID, errGetTenantID := utils.GetTenantIDFromHeader(r)
	if errGetTenantID != nil {
		slog.Error("Error obtaining tenantID from header", slog.Any("error", errGetTenantID))
		http.Error(w, "Invalid or missing X-TenantId header", http.StatusBadRequest)
		return
	}
	conn, err := h.cfg.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewScanClient(h.cfg, conn, h, tenantID)
	// Add the newly created client to the Hub
	h.Register(client)

	go client.ReadMessages()
	go client.WriteMessages()
}

// Run spins up the select statement for reading and writing from the Hub's go routines.
func (h *ScanHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client.GetID()] = client
		case client := <-h.unregister:
			if client, ok := h.clients[client.GetID()]; ok {
				if err := client.Close(); err != nil {
					slog.Error("Failed to close client",
						slog.String("client_id", client.GetID()),
						slog.Any("error", err))
					return
				}
				delete(h.clients, client.GetID())
			}
		case message := <-h.broadcast:
			for _, client := range h.clients {
				select {
				case client.GetSend() <- message:
				default:
					if err := client.Close(); err != nil {
						slog.Error("Failed to close client",
							slog.String("client_id", client.GetID()),
							slog.Any("error", err))
						return
					}
					delete(h.clients, client.GetID())
				}
			}
		}
	}
}

// Register will add clients to our clientList
func (h *ScanHub) Register(client common.IClient) {
	// Add Client
	h.register <- client
}

// Unregister will remove clients from the clientList
func (h *ScanHub) Unregister(client common.IClient) {
	h.unregister <- client
}

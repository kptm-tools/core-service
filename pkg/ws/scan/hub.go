package scan

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/utils"
)

type ScanHub struct {
	cfg          *common.Config
	clients      map[string]interfaces.IClient
	register     chan interfaces.IClient
	unregister   chan interfaces.IClient
	scanService  interfaces.IScanService
	authService  interfaces.IAuthService
	scanInterval time.Duration
}

var _ interfaces.IHub = (*ScanHub)(nil)

func NewScanHub(config *common.Config, scanService interfaces.IScanService, authService interfaces.IAuthService, scanIntervalSeconds int) *ScanHub {
	server := &ScanHub{
		cfg:          config,
		clients:      make(map[string]interfaces.IClient),
		register:     make(chan interfaces.IClient),
		unregister:   make(chan interfaces.IClient),
		scanService:  scanService,
		authService:  authService,
		scanInterval: time.Duration(scanIntervalSeconds) * time.Second,
	}
	return server
}

func (h *ScanHub) Serve(w http.ResponseWriter, r *http.Request) {
	slog.Info("1")
	otp, err := utils.GetOTPFromQuery(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	slog.Info("2")
	if !h.authService.VerifyOTP(otp) {
		slog.Warn("Client OTP has expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	slog.Info("3")
	tenantID, err := utils.GetTenantIDFromQuery(r)
	if err != nil {
		slog.Warn("Query is missing tenantID", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	slog.Info("4")
	conn, err := h.cfg.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewScanClient(h.cfg, conn, h, tenantID)
	slog.Info("5")
	// Add the newly created client to the Hub
	h.Register(client)
	slog.Info("6")
	// Since clients don't send messages to this hub, we don't need to read their messages
	go client.WriteMessages()
	go client.ReadMessages()
	slog.Info("7")
}

// Run spins up the select statement for managing clients and periodically sending scan data.
func (h *ScanHub) Run() {
	ticker := time.NewTicker(h.scanInterval)
	defer ticker.Stop()

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
		case <-ticker.C:
			for _, client := range h.clients {
				scanClient := client.(*ScanClient) // Assert back to ScanClient struct

				scans, err := h.scanService.GetCurrentScans(scanClient.tenantID)
				if err != nil {
					slog.Error("Failed to get scans",
						slog.String("client_id", client.GetID()),
						slog.String("tenant_id", scanClient.tenantID),
						slog.Any("error", err))
				}

				scanData, err := json.Marshal(scans)
				if err != nil {
					slog.Error("Failed to marshal scanData",
						slog.String("client_id", client.GetID()),
						slog.Any("error", err))
					continue
				}
				client.GetSend() <- scanData
			}
		}
	}
}

// Register will add clients to our clientList
func (h *ScanHub) Register(client interfaces.IClient) {
	// Add Client
	h.register <- client
}

// Unregister will remove clients from the clientList
func (h *ScanHub) Unregister(client interfaces.IClient) {
	h.unregister <- client
}

package scan

import (
	"context"
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
	clients      map[string]interfaces.IScanClient
	register     chan interfaces.IScanClient
	unregister   chan interfaces.IScanClient
	scanService  interfaces.IScanService
	authService  interfaces.IAuthService
	scanInterval time.Duration
}

// Ensure ScanHub implements IHub interface
var _ interfaces.IHub = (*ScanHub)(nil)

func NewScanHub(config *common.Config, scanService interfaces.IScanService, authService interfaces.IAuthService, scanIntervalSeconds int) *ScanHub {
	server := &ScanHub{
		cfg:          config,
		clients:      make(map[string]interfaces.IScanClient),
		register:     make(chan interfaces.IScanClient),
		unregister:   make(chan interfaces.IScanClient),
		scanService:  scanService,
		authService:  authService,
		scanInterval: time.Duration(scanIntervalSeconds) * time.Second,
	}
	return server
}

func (h *ScanHub) Serve(w http.ResponseWriter, r *http.Request) {
	otp, err := utils.GetOTPFromQuery(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !h.authService.VerifyOTP(otp) {
		slog.Warn("Client OTP has expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tenantID, err := utils.GetTenantIDFromQuery(r)
	if err != nil {
		slog.Warn("Query is missing tenantID", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	conn, err := h.cfg.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewScanClient(h.cfg, conn, h, tenantID)
	// Add the newly created client to the Hub
	h.Register(client)
	// Since clients don't send messages to this hub, we don't need to read their messages
	go client.WriteMessages()
	go client.ReadMessages()
}

// Run spins up the select statement for managing clients and periodically sending scan data.
func (h *ScanHub) Run() {
	ctx := context.Background()
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
				scans, err := h.scanService.GetCurrentScans(ctx, client.GetTenantID())
				if err != nil {
					slog.Error("Failed to get scans",
						slog.String("client_id", client.GetID()),
						slog.String("tenant_id", client.GetTenantID().String()),
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

// Register provides IHub interface compatibility by casting to IScanClient
func (h *ScanHub) Register(client interfaces.IClient) {
	if scanClient, ok := client.(interfaces.IScanClient); ok {
		h.register <- scanClient
	}
}

// Unregister provides IHub interface compatibility by casting to IScanClient
func (h *ScanHub) Unregister(client interfaces.IClient) {
	if scanClient, ok := client.(interfaces.IScanClient); ok {
		h.unregister <- scanClient
	}
}

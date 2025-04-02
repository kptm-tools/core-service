package ws

import (
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"log/slog"
	"net/http"
	"sync"
)

type HubScan struct {
	cfg *config.Config
	sync.RWMutex
	// messages are functions that are used to handle Events
	clients     HubClientScanList
	scanService interfaces.IScanService
}

var _ interfaces.IHubScanHandlers = (*HubReport)(nil)

func NewHubScan(scanService interfaces.IScanService) *HubScan {
	server := &HubScan{
		cfg:         config.LoadConfig(),
		clients:     make(HubClientScanList),
		scanService: scanService,
	}
	return server
}

func (h *HubScan) Serve(w http.ResponseWriter, r *http.Request) {
	tenantID, errGetTenantID := GetTenantIDFromHeader(r)
	if errGetTenantID != nil {
		slog.Error("Error obtaining tenantID from header", slog.Any("error", errGetTenantID))
		return
	}
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewHubScanClient(conn, h, tenantID)
	// Add the newly created client to the manager
	h.addClient(client)

	go client.readMessages()
	go client.writeMessages()
}

// addClient will add clients to our clientList
func (h *HubScan) addClient(client *HubClientScan) {
	// Lock so we can manipulate
	h.Lock()
	defer h.Unlock()

	// Add Client
	h.clients[client] = true
}

// removeClient will remove the client and clean up
func (h *HubScan) removeClient(client *HubClientScan) {
	h.Lock()
	defer h.Unlock()

	// Check if Client exists, then delete it
	if _, ok := h.clients[client]; ok {
		// close connection
		client.connection.Close()
		// remove
		delete(h.clients, client)
	}
}

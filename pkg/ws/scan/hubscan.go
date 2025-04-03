package scan

import (
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws"
	_ "github.com/kptm-tools/core-service/pkg/ws/interfaces"
	interfaces2 "github.com/kptm-tools/core-service/pkg/ws/interfaces"
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

var _ interfaces2.IHub = (*HubScan)(nil)

func NewHubScan(scanService interfaces.IScanService) *HubScan {
	server := &HubScan{
		cfg:         config.LoadConfig(),
		clients:     make(HubClientScanList),
		scanService: scanService,
	}
	return server
}

func (h *HubScan) Serve(w http.ResponseWriter, r *http.Request) {
	tenantID, errGetTenantID := ws.GetTenantIDFromHeader(r)
	if errGetTenantID != nil {
		slog.Error("Error obtaining tenantID from header", slog.Any("error", errGetTenantID))
		return
	}
	conn, err := ws.WebsocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewHubScanClient(conn, h, tenantID)
	var iclient interfaces2.IClient = client
	// Add the newly created client to the hub
	h.AddClient(&iclient)

	go client.ReadMessages()
	go client.WriteMessages()
}

// AddClient will add clients to our clientList
func (h *HubScan) AddClient(client *interfaces2.IClient) {
	// Lock so we can manipulate
	h.Lock()
	defer h.Unlock()

	// Add Client
	h.clients[(*client).GetScanClient()] = true
}

// RemoveClient will remove the client and clean up
func (h *HubScan) RemoveClient(client *interfaces2.IClient) {
	h.Lock()
	defer h.Unlock()

	// Check if Client exists, then delete it
	if _, ok := h.clients[(*client).GetScanClient()]; ok {
		// close connection
		(*client).GetScanClient().connection.Close()
		// remove
		delete(h.clients, (*client).GetScanClient())
	}
}

// RouteEvent is used to make sure the correct event goes into the correct handler
// not used right now but it is there if grows the application
func (h *HubScan) RouteEvent(event domain.Event, c *interfaces2.IClient) error {
	return nil
}

package ws

import (
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"log/slog"
	"net/http"
	"sync"
)

type HubReport struct {
	cfg *config.Config
	sync.RWMutex
	// handlers are functions that are used to handle Events
	handlers    map[string]EventReportHandler
	clients     HubClientReportList
	vulnService interfaces.IVulnerabilityService
}

var _ interfaces.IHubReportHandlers = (*HubReport)(nil)

func NewHubReport(vulnService interfaces.IVulnerabilityService) *HubReport {
	server := &HubReport{
		cfg:         config.LoadConfig(),
		clients:     make(HubClientReportList),
		handlers:    make(map[string]EventReportHandler),
		vulnService: vulnService,
	}
	server.setupEventHandlers()
	return server
}
func (h *HubReport) setupEventHandlers() {
	messageHandlers := NewMessageReportHandlers()
	h.handlers[EventSendMessage] = messageHandlers.InitialRequest
}

func (h *HubReport) Serve(w http.ResponseWriter, r *http.Request) {
	tenantID, errGetTenantID := GetTenantIDFromHeader(r)
	if errGetTenantID != nil {
		slog.Error("Error obtaining tenantID from header", slog.Any("error", errGetTenantID))
		return
	}
	scanID, errGetScanID := GetScanID(r)
	if errGetScanID != nil {
		slog.Error("Error obtaining scanID from path", slog.Any("error", errGetScanID))
		return
	}
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Error upgrading websocket", slog.Any("error", err))
		return
	}
	// Create New Client
	client := NewHubReportClient(conn, h, tenantID, scanID.String())
	// Add the newly created client to the manager
	h.addClient(client)

	go client.readMessages()
	go client.writeMessages()
}

// routeEvent is used to make sure the correct event goes into the correct handler
// not used right now but it is there if grows the application
func (h *HubReport) routeEvent(event domain.Event, c *HubClientReport) error {
	// Check if Handler is present in Map
	if handler, ok := h.handlers[event.Type]; ok {
		// Execute the handler and return any err
		if err := handler(event, c.tenantID, c.scanID); err != nil {
			return err
		}
		return nil
	} else {
		return ErrEventNotSupported
	}
}

// addClient will add Clients to our clientList
func (h *HubReport) addClient(client *HubClientReport) {
	// Lock so we can manipulate
	h.Lock()
	defer h.Unlock()

	// Add Client
	h.clients[client] = true
}

// removeClient will remove the client and clean up
func (h *HubReport) removeClient(client *HubClientReport) {
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

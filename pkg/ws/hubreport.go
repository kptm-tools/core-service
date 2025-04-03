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

var _ IHub = (*HubReport)(nil)

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
	h.handlers[EventInitialRequest] = messageHandlers.InitialRequest
	h.handlers[EventVectorUpdate] = messageHandlers.VectorUpdate
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
	conn, err := WebsocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Error upgrading websocket", slog.Any("error", err))
		return
	}
	//dataVulnerability := h.vulnService.GetScanVulnerabilities(scanID)
	dataVulnerability := []*VulnerabilityTypeData{}
	// Create New Client
	client := NewHubReportClient(conn, h, tenantID, scanID.String(), dataVulnerability)
	var interfaceClient IClient = client
	// Add the newly created client to the hub
	h.AddClient(&interfaceClient)

	go client.ReadMessages()
	go client.WriteMessages()
}

// routeEvent is used to make sure the correct event goes into the correct handler
// not used right now but it is there if grows the application
func (h *HubReport) RouteEvent(event domain.Event, c *IClient) error {
	// Check if Handler is present in Map
	if handler, ok := h.handlers[event.Type]; ok {
		// Execute the handler and return any err
		if err := handler(event, (*c).GetReportClient().tenantID, (*c).GetReportClient().scanID); err != nil {
			return err
		}
		return nil
	} else {
		return ErrEventNotSupported
	}
}

// addClient will add Clients to our clientList
func (h *HubReport) AddClient(client *IClient) {
	// Lock so we can manipulate
	h.Lock()
	defer h.Unlock()

	// Add Client
	h.clients[(*client).GetReportClient()] = true
}

// removeClient will remove the client and clean up
func (h *HubReport) RemoveClient(client *IClient) {
	h.Lock()
	defer h.Unlock()

	// Check if Client exists, then delete it
	if _, ok := h.clients[(*client).GetReportClient()]; ok {
		// close connection
		(*client).GetReportClient().connection.Close()
		// remove
		delete(h.clients, (*client).GetReportClient())
	}
}

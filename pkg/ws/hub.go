package ws

import (
	"errors"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/handler"
	"net/http"
	"sync"
)

type Hub struct {
	cfg *config.Config
	sync.RWMutex
	// handlers are functions that are used to handle Events
	handlers    map[string]EventHandler
	clients     HubClientList
	scanService interfaces.IScanService
}

var (
	ErrEventNotSupported = errors.New("this event type is not supported")
)

var (
	/**
	websocketUpgrader is used to upgrade incomming HTTP requests into a persitent websocket connection
	*/
	websocketUpgrader = websocket.Upgrader{
		// Apply the Origin Checker
		CheckOrigin:     checkOrigin,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

// checkOrigin will check origin and return true if its allowed
func checkOrigin(r *http.Request) bool {
	return true
}

var _ handler.WebSocketMessageHandler = (*Hub)(nil)

func NewHub(scanService interfaces.IScanService) *Hub {
	server := &Hub{
		cfg:         config.LoadConfig(),
		clients:     make(HubClientList),
		handlers:    make(map[string]EventHandler),
		scanService: scanService,
	}
	server.setupEventHandlers()
	return server
}
func (h *Hub) setupEventHandlers() {
	h.handlers[EventSendMessage] = SendMessageHandler
}

func (h *Hub) ServeScan(w http.ResponseWriter, r *http.Request) {
	tenantID := "" //handlers.GetTenantIDFromHeader(r)
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewHubClient(conn, h, tenantID)
	// Add the newly created client to the manager
	h.addClient(client)

	go client.readMessages()
	go client.writeMessages()
}

func (h *Hub) ServeReport(w http.ResponseWriter, r *http.Request) {
	tenantID := "" //handlers.GetTenantIDFromHeader(r)
	scanID := ""
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewHubClientWithScanID(conn, h, tenantID, scanID)
	// Add the newly created client to the manager
	h.addClient(client)

	go client.readMessages()
	go client.writeMessages()
}

// routeEvent is used to make sure the correct event goes into the correct handler
// not used right now but it is there if grows the application
func (h *Hub) routeEvent(event Event, c *HubClient) error {
	// Check if Handler is present in Map
	if handler, ok := h.handlers[event.Type]; ok {
		// Execute the handler and return any err
		if err := handler(event, c); err != nil {
			return err
		}
		return nil
	} else {
		return ErrEventNotSupported
	}
}

// addClient will add clients to our clientList
func (h *Hub) addClient(client *HubClient) {
	// Lock so we can manipulate
	h.Lock()
	defer h.Unlock()

	// Add Client
	h.clients[client] = true
}

// removeClient will remove the client and clean up
func (h *Hub) removeClient(client *HubClient) {
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

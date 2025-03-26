package handlers

import (
	"errors"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"net/http"
	"sync"
)

type WsServer struct {
	cfg *config.Config
	sync.RWMutex
	// handlers are functions that are used to handle Events
	handlers    map[string]EventHandler
	clients     WsClientList
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

var _ interfaces.IWsHandlers = (*WsServer)(nil)

func NewWsHandlers(scanService interfaces.IScanService) *WsServer {
	server := &WsServer{
		cfg:         config.LoadConfig(),
		clients:     make(WsClientList),
		handlers:    make(map[string]EventHandler),
		scanService: scanService,
	}
	server.setupEventHandlers()
	return server
}
func (m *WsServer) setupEventHandlers() {
	m.handlers[EventSendMessage] = SendMessageHandler
	m.handlers[EventChangeRoom] = ChatRoomHandler
}

func (ws *WsServer) Serve(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := GetTenantIDFromHeader(r)
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	// Create New Client
	client := NewWsClient(conn, ws, tenantID)
	// Add the newly created client to the manager
	ws.addClient(client)

	go client.readMessages()
	go client.writeMessages()
}

// routeEvent is used to make sure the correct event goes into the correct handler
func (ws *WsServer) routeEvent(event Event, c *WsClient) error {
	// Check if Handler is present in Map
	if handler, ok := ws.handlers[event.Type]; ok {
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
func (ws *WsServer) addClient(client *WsClient) {
	// Lock so we can manipulate
	ws.Lock()
	defer ws.Unlock()

	// Add Client
	ws.clients[client] = true
}

// removeClient will remove the client and clean up
func (ws *WsServer) removeClient(client *WsClient) {
	ws.Lock()
	defer ws.Unlock()

	// Check if Client exists, then delete it
	if _, ok := ws.clients[client]; ok {
		// close connection
		client.connection.Close()
		// remove
		delete(ws.clients, client)
	}
}

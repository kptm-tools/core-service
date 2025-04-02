package ws

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/domain"
	"log"
	"time"
)

type HubClientReportList map[*HubClientReport]bool

type HubClientReport struct {
	// the websocket connection
	connection *websocket.Conn

	// manager is the manager used to manage the client
	manager *HubReport
	// egress is used to avoid concurrent writes on the WebSocket
	egress chan domain.Event
	// tenantID is used to know what room user is in
	tenantID string
	scanID   string
}

// NewHubScanClient is used to initialize a new Client with all required values initialized
func NewHubReportClient(conn *websocket.Conn, manager *HubReport, tenantID string, scanID string) *HubClientReport {
	return &HubClientReport{
		connection: conn,
		manager:    manager,
		egress:     make(chan domain.Event),
		tenantID:   tenantID,
		scanID:     scanID,
	}
}

// readMessages will start the client to read messages and handle them
// appropriatly.
// This is suppose to be ran as a goroutine
func (c *HubClientReport) readMessages() {
	defer func() {
		// Graceful Close the Connection once this
		// function is done
		c.manager.removeClient(c)
	}()
	// Set Max Size of Messages in Bytes
	c.connection.SetReadLimit(512)
	// Configure Wait time for Pong response, use Current time + pongWait
	// This has to be done here to set the first initial timer.
	if err := c.connection.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		log.Println(err)
		return
	}
	// Configure how to handle Pong responses
	c.connection.SetPongHandler(c.pongHandler)

	// Loop Forever
	for {
		// ReadMessage is used to read the next message in queue
		// in the connection
		_, payload, err := c.connection.ReadMessage()

		if err != nil {
			// If Connection is closed, we will Recieve an error here
			// We only want to log Strange errors, but simple Disconnection
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error reading message: %v", err)
			}
			break // Break the loop to close conn & Cleanup
		}
		// Marshal incoming data into a Event struct
		var request domain.Event
		if err := json.Unmarshal(payload, &request); err != nil {
			log.Printf("error marshalling message: %v", err)
			break // Breaking the connection here might be harsh xD
		}
		// Route the Event
		if err := c.manager.routeEvent(request, c); err != nil {
			log.Println("Error handeling Message: ", err)
		}
	}
}

// pongHandler is used to handle PongMessages for the Client
func (c *HubClientReport) pongHandler(pongMsg string) error {
	// Current time + Pong Wait time
	return c.connection.SetReadDeadline(time.Now().Add(pongWait))
}

// writeMessages is a process that listens for new messages to output to the Client
func (c *HubClientReport) writeMessages() {
	// Create a ticker that triggers a ping at given interval
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		// Graceful close if this triggers a closing
		c.manager.removeClient(c)
	}()

	for {
		select {
		case message, ok := <-c.egress:
			// Ok will be false Incase the egress channel is closed
			if !ok {
				// manager has closed this connection channel, so communicate that to frontend
				if err := c.connection.WriteMessage(websocket.CloseMessage, nil); err != nil {
					// Log that the connection is closed and the reason
					log.Println("connection closed: ", err)
				}
				// Return to close the goroutine
				return
			}

			data, err := json.Marshal(message)
			if err != nil {
				log.Println(err)
				return // closes the connection, should we really
			}
			// Write a Regular text message to the connection
			if err := c.connection.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println(err)
			}
			log.Println("sent message")
		case <-ticker.C:
			log.Println("ping")
			// Send the Ping
			if err := c.connection.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Println("writemsg: ", err)
				return // return to break this goroutine triggeing cleanup
			}
		}

	}
}

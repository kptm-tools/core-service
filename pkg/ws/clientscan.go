package ws

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"log"
	"log/slog"
	"strconv"
	"time"
)

type HubClientScanList map[*HubClientScan]bool

type HubClientScan struct {
	// the websocket connection
	connection *websocket.Conn

	// manager is the manager used to manage the client
	manager *HubScan
	// tenantID is used to know what room user is in
	tenantID string
}

// NewHubScanClient is used to initialize a new Client with all required values initialized
func NewHubScanClient(conn *websocket.Conn, manager *HubScan, tenantID string) *HubClientScan {
	return &HubClientScan{
		connection: conn,
		manager:    manager,
		tenantID:   tenantID,
	}
}

// readMessages will start the client to read messages and handle them
// appropriatly.
// This is suppose to be ran as a goroutine
func (c *HubClientScan) readMessages() {
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
		_, _, err := c.connection.ReadMessage()

		if err != nil {
			// If Connection is closed, we will Recieve an error here
			// We only want to log Strange errors, but simple Disconnection
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error reading message: %v", err)
			}
			break // Break the loop to close conn & Cleanup
		}
	}
}

// pongHandler is used to handle PongMessages for the Client
func (c *HubClientScan) pongHandler(pongMsg string) error {
	// Current time + Pong Wait time
	return c.connection.SetReadDeadline(time.Now().Add(pongWait))
}

// writeMessages is a process that listens for new messages to output to the Client
func (c *HubClientScan) writeMessages() {
	// Create a ticker that triggers a ping at given interval
	ticker := time.NewTicker(pingInterval)
	scanInterval, _ := strconv.Atoi(c.manager.cfg.Websocket.IntervalScanRefresh)
	scanIntervalDuration := time.Duration(scanInterval) * time.Second
	tickerScan := time.NewTicker(scanIntervalDuration)
	defer func() {
		ticker.Stop()
		// Graceful close if this triggers a closing
		c.manager.removeClient(c)
	}()

	for {
		select {
		case <-ticker.C:
			log.Println("ping")
			// Send the Ping
			if err := c.connection.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Println("writemsg: ", err)
				return // return to break this goroutine triggeing cleanup
			}
		case <-tickerScan.C:
			scans, errGetScans := c.manager.scanService.GetCurrentScans(c.tenantID)
			if errGetScans != nil {
				slog.Error("Not able to get scans", slog.Any("tenantID", c.tenantID), slog.Any("error", errGetScans))
			}
			data, err := json.Marshal(scans)
			if err != nil {
				log.Println(err)
				return // closes the connection, should we really
			}
			if err := c.connection.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println(err)
			}
		}

	}
}

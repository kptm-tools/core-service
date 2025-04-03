package scan

import (
	"encoding/json"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type ScanClientList map[*ScanClient]bool

type ScanClient struct {
	ID string
	// config
	config *common.Config
	// the websocket connection
	connection *websocket.Conn

	// hub is the hub used to manage the client
	hub *ScanHub
	// tenantID is used to know what room user is in
	tenantID string
	// send
	send chan []byte
}

// NewHubScanClient is used to initialize a new Client with all required values initialized
func NewScanClient(
	cfg *common.Config,
	conn *websocket.Conn,
	hub *ScanHub,
	tenantID string,
) *ScanClient {
	return &ScanClient{
		ID:         uuid.NewString(),
		config:     cfg,
		connection: conn,
		hub:        hub,
		tenantID:   tenantID,
		send:       make(chan []byte, 256),
	}
}

// ReadMessages will start the client to read messages and handle them
// appropriatly.
// This is meant to be ran as a goroutine. In this case, we have a broadcast.
func (c *ScanClient) ReadMessages() {
	slog.Debug("Reading messages...")

	// Set Max Size of Messages in Bytes
	c.connection.SetReadLimit(512)
	// Configure Wait time for Pong response, use Current time + pongWait
	// This has to be done here to set the first initial timer.
	if err := c.connection.SetReadDeadline(time.Now().Add(c.config.PongWait)); err != nil {
		slog.Error("Error setting read deadline for client", slog.String("client_id", c.ID), slog.Any("error", err))
	}
	// Configure how to handle Pong responses
	c.connection.SetPongHandler(c.pongHandler)

	// Loop Forever
	for {
		// ReadMessage is used to read the next message in queue
		// in the connection
		_, message, err := c.connection.ReadMessage()
		if err != nil {
			// If Connection is closed, we will Recieve an error here
			// We only want to log Strange errors, but simple Disconnection
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("Error reading message", slog.String("client_id", c.ID), slog.Any("error", err))
			}
			break // Break the loop to close conn & Cleanup
		}
		// Broadcast the message
		c.hub.broadcast <- message
	}
}

// writeMessages is a process that listens for new messages to output to the Client
func (c *ScanClient) WriteMessages() {
	// Create a ticker that triggers a ping at given interval
	ticker := time.NewTicker(c.config.PingInterval)

	scanInterval := 2
	scanIntervalDuration := time.Duration(scanInterval) * time.Second
	tickerScan := time.NewTicker(scanIntervalDuration)

	defer func() {
		ticker.Stop()
		// Graceful close if this triggers a closing
		c.hub.Unregister(c)
	}()

	for {
		select {
		case <-ticker.C:
			// Send the Ping
			if err := c.connection.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Println("writemsg: ", err)
				return // return to break this goroutine triggeing cleanup
			}
		case <-tickerScan.C:
			scans, errGetScans := c.hub.scanService.GetCurrentScans(c.tenantID)
			if errGetScans != nil {
				slog.Error("Not able to get scans", slog.Any("tenantID", c.tenantID), slog.Any("error", errGetScans))
			}
			scanData, err := json.Marshal(scans)
			if err != nil {
				slog.Error("Failed to marshal scanData",
					slog.Any("client_id", c.ID),
					slog.Any("error", err))
				log.Println(err)
				return // closes the connection, should we really
			}
			if err := c.connection.WriteMessage(websocket.TextMessage, scanData); err != nil {
				slog.Error("Error writing scan message", slog.String("client_id", c.ID), slog.Any("error", err))
			}
		}
	}
}

// pongHandler is used to handle PongMessages for the Client
func (c *ScanClient) pongHandler(pongMsg string) error {
	// Current time + Pong Wait time
	return c.connection.SetReadDeadline(time.Now().Add(c.config.PongWait))
}

func (c *ScanClient) GetSend() chan []byte {
	return c.send
}

func (c *ScanClient) GetID() string {
	return c.ID
}

func (c *ScanClient) GetHub() common.IHub {
	return c.hub
}

func (c *ScanClient) Close() error {
	close(c.send)
	return c.connection.Close()
}

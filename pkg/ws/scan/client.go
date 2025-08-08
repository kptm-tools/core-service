package scan

import (
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
	tenantID uuid.UUID

	// outgoing is the channel used to outgoing data to the client.
	// It represents the data that the Client is about to send out through it's connection.
	// It's the queue of messages destined to leave the Client process.
	outgoing chan []byte
}

// NewScanClient is used to initialize a new Client with all required values initialized
func NewScanClient(
	cfg *common.Config,
	conn *websocket.Conn,
	hub *ScanHub,
	tenantID uuid.UUID,
) *ScanClient {
	return &ScanClient{
		ID:         uuid.NewString(),
		config:     cfg,
		connection: conn,
		hub:        hub,
		tenantID:   tenantID,
		outgoing:   make(chan []byte, 256),
	}
}

// ReadMessages will start the client to read messages and handle pongs.
// This is meant to be ran as a go routine
func (c *ScanClient) ReadMessages() {
	defer func() {
		c.hub.Unregister(c)
	}()

	// Set Max Size of Messages in Bytes
	c.connection.SetReadLimit(512)
	// Configure Wait time for Pong response, use Current time + pongWait
	// This has to be done here to set the first initial timer.
	if err := c.connection.SetReadDeadline(time.Now().Add(c.config.PongWait)); err != nil {
		slog.Error("Error setting intitial read deadline for client", slog.String("client_id", c.ID), slog.Any("error", err))
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
			// If Connection is closed, we will Receive an error here
			// We only want to log Strange errors, but simple Disconnection
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("Unexpected websocket close error",
					slog.String("client_id", c.ID),
					slog.Any("error", err))
			} else {
				slog.Debug("Client connection closed normally",
					slog.String("client_id", c.ID))
			}
			break // Break the loop to close conn & Cleanup
		}

		// We are not expecting any client messages for scans, so we just read and discard them.
		slog.Debug("Received a non-pong message, discarding", slog.String("client_id", c.ID))
	}
}

// WriteMessages is a process that listens for new messages to output to the Client
func (c *ScanClient) WriteMessages() {
	// Create a ticker that triggers a ping at given interval
	ticker := time.NewTicker(c.config.PingInterval)

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
		case message, ok := <-c.outgoing:
			if !ok {
				c.connection.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.connection.NextWriter(websocket.TextMessage)
			if err != nil {
				slog.Error("Failed to create a Writer for the next message to send", slog.Any("error", err))
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}

		}
	}
}

// pongHandler is used to handle PongMessages for the Client
func (c *ScanClient) pongHandler(pongMsg string) error {
	// Current time + Pong Wait time
	slog.Debug("Received pong from server", slog.String("client_id", c.ID))
	return c.connection.SetReadDeadline(time.Now().Add(c.config.PongWait))
}

func (c *ScanClient) GetSend() chan []byte {
	return c.outgoing
}

func (c *ScanClient) GetID() string {
	return c.ID
}

func (c *ScanClient) Close() error {
	close(c.outgoing)
	return c.connection.Close()
}

func (c *ScanClient) GetTenantID() uuid.UUID {
	return c.tenantID
}

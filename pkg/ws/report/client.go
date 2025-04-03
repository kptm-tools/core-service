package report

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type ReportClient struct {
	ID string

	config *common.Config

	// connection refers to the websocket connection
	connection *websocket.Conn

	// hub is the hub used to manage the client
	hub *ReportHub

	// send is the channel used to send data to the client
	send chan []byte
}

func NewReportClient(
	cfg *common.Config,
	conn *websocket.Conn,
	hub *ReportHub,
) *ReportClient {
	return &ReportClient{
		ID:         uuid.NewString(),
		config:     cfg,
		connection: conn,
		hub:        hub,
		send:       make(chan []byte, 256),
	}
}

// ReadMessages will start the client to read and handle messages.
// It is meant to be ran as a go routine.
func (c *ReportClient) ReadMessages() {
	defer c.hub.Unregister(c)
	for {
		messageType, payload, err := c.connection.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("Error reading message", slog.Any("error", err))
			}
			break
		}
		slog.Info("Received message from client",
			slog.Group("message", slog.Int("message_type", messageType), slog.String("message", string(payload))),
		)

		// Route the Message
		var msg common.Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			slog.Error("failed to unmarshal message", slog.Any("error", err))
			continue
		}
		routeErr := c.hub.routeMessage(msg, c)
		if routeErr != nil {
			slog.Error("Failed to route message", slog.Any("error", routeErr))
		}
	}
}

// WriteMessages is a process that listens for new messages to output to the Client
func (c *ReportClient) WriteMessages() {
	defer c.hub.Unregister(c)

	for {
		msg, ok := <-c.send
		if !ok {
			if err := c.connection.WriteMessage(websocket.CloseMessage, nil); err != nil {
				slog.Warn("connection closed", slog.Any("error", err))
			}
			return
		}

		// Marshal the message, it must follow common Message struct
		if err := c.connection.WriteMessage(websocket.TextMessage, msg); err != nil {
			slog.Error("Failed to send message", slog.Any("error", err))
		}

		slog.Info("Message sent")
	}
}

// pongHandler is used to handle PongMessages for the Client
func (c *ReportClient) pongHandler() error {
	// Current time + Pong Wait time
	slog.Debug("Received pong from server", slog.String("client_id", c.ID))
	return c.connection.SetReadDeadline(time.Now().Add(c.config.PongWait))
}

func (c *ReportClient) GetSend() chan []byte {
	return c.send
}

func (c *ReportClient) GetID() string {
	return c.ID
}

func (c *ReportClient) GetHub() common.IHub {
	return c.hub
}

func (c *ReportClient) Close() error {
	close(c.send)
	return c.connection.Close()
}

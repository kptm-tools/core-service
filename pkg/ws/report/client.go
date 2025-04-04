package report

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type ReportClient struct {
	ID string

	config *common.Config

	// connection refers to the websocket connection
	connection *websocket.Conn

	// hub is the hub used to manage the client
	hub *ReportHub

	// outgoing is the channel used to outgoing data to the client
	// It represents the data that the Client is about to send out through it's connection.
	// It's the queue of messages destined to leave the Client process.
	outgoing chan []byte

	// vectorStatus represents the currently selected vectors by the client. This map must be initially
	// populated on an initial connection, and updated on each vector_update message.
	vectorStatus map[enums.WeaknessType]float64
}

func NewReportClient(
	cfg *common.Config,
	conn *websocket.Conn,
	hub *ReportHub,
) *ReportClient {
	return &ReportClient{
		ID:           uuid.NewString(),
		config:       cfg,
		connection:   conn,
		hub:          hub,
		outgoing:     make(chan []byte, 256),
		vectorStatus: make(map[enums.WeaknessType]float64),
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
		msg, ok := <-c.outgoing
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
	return c.outgoing
}

func (c *ReportClient) GetID() string {
	return c.ID
}

func (c *ReportClient) GetHub() common.IHub {
	return c.hub
}

func (c *ReportClient) Close() error {
	close(c.outgoing)
	return c.connection.Close()
}

func (c *ReportClient) GetVectorStatus() map[enums.WeaknessType]float64 {
	return c.vectorStatus
}

func (c *ReportClient) SetVectorStatus(newVectorStatus map[enums.WeaknessType]float64) {
	c.vectorStatus = newVectorStatus
	slog.Debug("New vector status set", slog.Any("vector_status", c.vectorStatus))
}

func (c *ReportClient) UpdateVector(weakness enums.WeaknessType, newVal float64) {
	c.vectorStatus[weakness] = newVal
}

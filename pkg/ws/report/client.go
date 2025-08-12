package report

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
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
	vectorStatus map[enums.OwaspCategory]float64

	roomID string
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
		vectorStatus: make(map[enums.OwaspCategory]float64),
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
				slog.Error("Unexpected websocket close error",
					slog.String("client_id", c.ID),
					slog.String("room_id", c.roomID),
					slog.Any("error", err))
			} else {
				slog.Debug("Client connection closed normally",
					slog.String("client_id", c.ID),
					slog.String("room_id", c.roomID))
			}
			// Always try to remove from room on disconnect, but handle empty room ID gracefully
			if c.roomID != "" {
				c.GetHubReport().RemoveFromRoom(c.roomID)
			}
			break
		}
		slog.Info("Received message from client",
			slog.Group("message", slog.Int("message_type", messageType), slog.String("message", string(payload))),
		)

		// Route the Message
		var msg common.Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			slog.Error("Failed to unmarshal message",
				slog.String("client_id", c.ID),
				slog.String("room_id", c.roomID),
				slog.String("raw_message", string(payload)),
				slog.Any("error", err))
			c.sendErrorMessage("Failed to parse message")
			continue
		}
		routeErr := c.hub.routeMessage(msg, c)
		if routeErr != nil {
			slog.Error("Failed to route message",
				slog.String("client_id", c.ID),
				slog.String("room_id", c.roomID),
				slog.String("message_type", msg.Type),
				slog.Any("error", routeErr))
			c.sendErrorMessage(routeErr.Error())
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
				slog.Warn("Failed to send close message",
					slog.String("client_id", c.ID),
					slog.String("room_id", c.roomID),
					slog.Any("error", err))
			} else {
				slog.Debug("Close message sent successfully",
					slog.String("client_id", c.ID),
					slog.String("room_id", c.roomID))
			}
			return
		}

		// Marshal the message, it must follow common Message struct
		if err := c.connection.WriteMessage(websocket.TextMessage, msg); err != nil {
			slog.Error("Failed to send message to client",
				slog.String("client_id", c.ID),
				slog.String("room_id", c.roomID),
				slog.Any("error", err))
			// Connection is likely broken, close the client
			return
		}

		slog.Debug("Message sent successfully",
			slog.String("client_id", c.ID),
			slog.String("room_id", c.roomID))
	}
}

// pongHandler is used to handle PongMessages for the Client
func (c *ReportClient) pongHandler() error {
	// Current time + Pong Wait time
	slog.Debug("Received pong from client",
		slog.String("client_id", c.ID),
		slog.String("room_id", c.roomID))

	err := c.connection.SetReadDeadline(time.Now().Add(c.config.PongWait))
	if err != nil {
		slog.Error("Failed to set read deadline on pong",
			slog.String("client_id", c.ID),
			slog.String("room_id", c.roomID),
			slog.Any("error", err))
	}
	return err
}

func (c *ReportClient) GetSend() chan []byte {
	return c.outgoing
}

func (c *ReportClient) GetID() string {
	return c.ID
}

func (c *ReportClient) Close() error {
	slog.Debug("Closing client connection",
		slog.String("client_id", c.ID),
		slog.String("room_id", c.roomID))

	// Close the outgoing channel to signal WriteMessages to stop
	close(c.outgoing)

	// Close the websocket connection
	err := c.connection.Close()
	if err != nil {
		slog.Error("Failed to close websocket connection",
			slog.String("client_id", c.ID),
			slog.String("room_id", c.roomID),
			slog.Any("error", err))
	} else {
		slog.Debug("Client connection closed successfully",
			slog.String("client_id", c.ID),
			slog.String("room_id", c.roomID))
	}

	return err
}

func (c *ReportClient) GetVectorStatus() map[enums.OwaspCategory]float64 {
	return c.vectorStatus
}

func (c *ReportClient) SetVectorStatus(newVectorStatus map[enums.OwaspCategory]float64) {
	c.vectorStatus = newVectorStatus
	slog.Debug("New vector status set", slog.Any("vector_status", c.vectorStatus))
}

func (c *ReportClient) UpdateVector(weakness enums.OwaspCategory, newVal float64) {
	c.vectorStatus[weakness] = newVal
}

func (c *ReportClient) sendErrorMessage(message string) {
	errorPayload := dto.ErrorResponse{
		Message: message,
	}
	errorPayloadBytes, err := json.Marshal(errorPayload)
	if err != nil {
		slog.Error("Failed to marshal error response payload",
			slog.String("client_id", c.ID),
			slog.Any("error", err))
		return
	}

	errorMessage := common.Message{
		Type:    "error",
		Payload: errorPayloadBytes,
	}
	errMessageBytes, err := json.Marshal(errorMessage)
	if err != nil {
		slog.Error("Failed to marshal error message",
			slog.String("client_id", c.ID),
			slog.Any("error", err))
		return
	}

	c.outgoing <- errMessageBytes
}

func (c *ReportClient) GetHubReport() interfaces.IHubReport {
	return c.hub
}

func (c *ReportClient) SetRoomID(scanID string) {
	c.roomID = scanID
}

func (c *ReportClient) GetRoomID() string {
	return c.roomID
}

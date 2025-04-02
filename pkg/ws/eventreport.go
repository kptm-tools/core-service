package ws

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"time"
)

// EventReportHandler is a function signature that is used to affect messages on the socket and triggered
// depending on the type
type EventReportHandler func(event domain.Event, tenantID, scanID string) error

// If we want to add new type of event we start here
const (
	// EventSendMessage is the event name for new chat messages sent
	EventSendMessage = "send_message"
	// EventNewMessage is a response to send_message
	EventNewMessage = "new_message"
)

// SendMessageEvent is the payload sent in the
// send_message event
type SendMessageEvent struct {
	Message string `json:"message"`
}

// NewMessageEvent is returned when responding to send_message
type NewMessageEvent struct {
	SendMessageEvent
	Sent time.Time `json:"sent"`
}

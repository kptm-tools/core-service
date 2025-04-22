package common

import (
	"encoding/json"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/dto"
)

// Message represents the DTO struct being sent over WebSocket
// Used to differ between different actions
type Message struct {
	// Type is the message type sent
	Type string `json:"type"`
	// Payload is the data Based on the Type
	Payload json.RawMessage `json:"payload"`
}

func BuildServerMessageBytes(messageType dto.ServerMessageType, payload json.RawMessage) ([]byte, error) {
	msg := Message{
		Type:    messageType.String(),
		Payload: payload,
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal websocket message: %w", err)
	}

	return msgBytes, nil
}

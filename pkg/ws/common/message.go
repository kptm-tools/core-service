package common

import "encoding/json"

// Message represents the DTO struct being sent over WebSocket
// Used to differ between different actions
type Message struct {
	// Type is the message type sent
	Type string `json:"type"`
	// Payload is the data Based on the Type
	Payload json.RawMessage `json:"payload"`
}

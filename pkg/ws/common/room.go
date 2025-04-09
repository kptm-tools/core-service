package common

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

// Room represents the DTO struct being sent over WebSocket
// Used to differ between different actions
type Room struct {
	// Vulnerabilities is the array of vulnerabilities
	Vulnerabilities []*domain.Vulnerability `json:"vulnerabilities"`
	// Payload is the data Based on the Type
	AmountOfClients int `json:"amount_of_clients"`
}

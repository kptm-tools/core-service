package report

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"sync"
)

// ReportRoom represents the DTO struct being sent over WebSocket
// Used to differ between different actions
type ReportRoom struct {
	scanID string
	// Vulnerabilities is the array of vulnerabilities
	Vulnerabilities []*domain.Vulnerability `json:"vulnerabilities"`
	// Payload is the data Based on the Type
	AmountOfClients int `json:"amount_of_clients"`
	mu              sync.Mutex
}

/*func NewReportRoom(scanID string, data []*domain.Vulnerability) *ReportRoom {
	return &ReportRoom{
		scanID:          scanID,
		mu:              sync.Mutex{},
		Vulnerabilities: data,
		AmountOfClients: 0,
	}
}*/

func NewReportRoom(scanID string) *ReportRoom {
	return &ReportRoom{
		scanID:          scanID,
		mu:              sync.Mutex{},
		Vulnerabilities: []*domain.Vulnerability{},
		AmountOfClients: 0,
	}
}

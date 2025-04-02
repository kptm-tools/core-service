package ws

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

// EventReportHandler is a function signature that is used to affect messages on the socket and triggered
// depending on the type
type EventReportHandler func(event domain.Event, tenantID, scanID string) error

// If we want to add new type of event we start here
const (
	// EventInitialRequest is the event name for starting the request
	EventInitialRequest = "initial_data_request"
	// EventVectorUpdate is the event name for updating the vector
	EventVectorUpdate = "vector_update"
)

// InitialDataRequestMessageEvent is the payload sent in EventInitialRequest
type InitialDataRequestMessageEvent struct {
	ScanID string `json:"scan_id"`
}

// VectorUpdateMessageEvent is the payload sent in EventVectorUpdate
type VectorUpdateMessageEvent struct {
	VulnerabilityTypeName string `json:"vulnerability_type_name"`
	NewValue              string `json:"new_value"`
}

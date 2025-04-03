package wshandlers

import (
	"log/slog"

	"github.com/kptm-tools/core-service/pkg/ws/common"
)

const (
	MessageInitialRequest = "initial_data_request"
)

type InitialRequestHandler struct{}

func NewInitialRequestHandler() *InitialRequestHandler {
	return &InitialRequestHandler{}
}

// InitialDataRequestMessageEvent is the payload sent in EventInitialRequest
type InitialDataRequestMessage struct {
	ScanID string `json:"scan_id"`
}

func (h *InitialRequestHandler) Handle(msg common.Message, client common.IClient) error {
	slog.Debug("Handling initial request message...")
	return nil
}

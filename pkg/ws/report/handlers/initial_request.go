package wshandlers

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/utils"
)

const (
	MessageInitialRequest = "initial_data_request"
)

// InitialRequestMessage is the payload sent in a MessageInitialRequest
type InitialRequestMessage struct {
	ScanID string `json:"scan_id"`
}

type InitialRequestHandler struct {
	scanService interfaces.IScanService
}

func NewInitialRequestHandler(scanService interfaces.IScanService) *InitialRequestHandler {
	return &InitialRequestHandler{
		scanService: scanService,
	}
}

// InitialDataRequestMessage is the payload sent in EventInitialRequest
type InitialDataRequestMessage struct {
	ScanID string `json:"scan_id"`
}

func (h *InitialRequestHandler) Handle(msg common.Message, client common.IReportClient) error {
	slog.Debug("Handling initial request message...")

	var initialRequestMessage InitialRequestMessage
	if err := json.Unmarshal(msg.Payload, &initialRequestMessage); err != nil {
		return fmt.Errorf("failed to unmarshal initialRequestMessage payload: %w", err)
	}

	scanID, err := uuid.Parse(initialRequestMessage.ScanID)
	if err != nil {
		return fmt.Errorf("scanID is an invalid UUID: %s", initialRequestMessage.ScanID)
	}

	vulns, err := h.scanService.GetScanVulnerabilities(scanID)
	if err != nil {
		return fmt.Errorf("failed to get vulnerabilities for scan %s: %w", scanID.String(), err)
	}

	client.SetVectorStatus(utils.GetMaxCVSSPerType(vulns))
	return nil
}

package wshandlers

import (
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
)

type InitialRequestHandler struct {
	scanService interfaces.IScanService
}

func NewInitialRequestHandler(scanService interfaces.IScanService) *InitialRequestHandler {
	return &InitialRequestHandler{
		scanService: scanService,
	}
}

func (h *InitialRequestHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling initial request message...")

	var initialRequestMessage dto.InitialDataRequest
	if err := json.Unmarshal(msg.Payload, &initialRequestMessage); err != nil {
		slog.Error("Failed to unmarshal initialRequestMessage payload", slog.Any("error", err))
		return customerrors.NewParseError("failed to unmarshal initialRequestMessage payload", err)
	}

	// Determine scanID - prefer payload for backward compatibility, fallback to client roomID
	var scanIDStr string
	if initialRequestMessage.ScanID != "" {
		// Use scanID from payload (backward compatibility)
		scanIDStr = initialRequestMessage.ScanID
	} else {
		// Fallback to client's roomID (new approach via query param)
		scanIDStr = client.GetRoomID()
		if scanIDStr == "" {
			return customerrors.NewParseError("scanID not provided in payload and client has no roomID", nil)
		}
	}

	scanID, err := uuid.Parse(scanIDStr)
	if err != nil {
		return customerrors.NewParseError("scanID is an invalid UUID", err)
	}

	client.GetHubReport().AddToRoom(scanID.String())
	client.SetRoomID(scanID.String())
	vulns := client.GetHubReport().GetRoomVulnerabilities(scanID.String())
	if vulns == nil {
		slog.Error("Failed to get vulnerabilities for scan", slog.String("scan_id", scanID.String()))
		vulns = []tools.Vulnerability{} // Initialize empty slice to prevent nil pointer
	}

	payload := reportutils.BuildVulnerabilityTypeData(vulns)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal initial data response", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal initial data response")
	}

	msgBytes, err := common.BuildServerMessageBytes(dto.MessageInitialDataResponse, payloadBytes)
	if err != nil {
		slog.Error("Failed to marshal message", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal message")
	}

	client.SetVectorStatus(reportutils.GetMaxCVSSPerType(vulns))
	client.GetSend() <- msgBytes
	return nil
}

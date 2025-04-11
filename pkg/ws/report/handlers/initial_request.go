package wshandlers

import (
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/report/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
)

const (
	MessageInitialRequest = "initial_data_request"
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

	scanID, err := uuid.Parse(initialRequestMessage.ScanID)
	if err != nil {
		return customerrors.NewParseError("scanID is an invalid UUID", nil)
	}
	client.GetHubReport().AddToRoom(scanID.String())
	client.SetRoomID(scanID.String())
	vulns := client.GetHubReport().GetRoomVulnerabilities(scanID.String())
	if vulns == nil {
		slog.Error("Failed to get vulnerabilities for scan", slog.String("scan_id", scanID.String()), slog.Any("error", err))
		return customerrors.NewServerSideError("failed to get vulnerabilities for scan")
	}

	response := reportutils.BuildVulnerabilityTypeData(vulns)
	responseBytes, err := json.Marshal(response)
	if err != nil {
		slog.Error("Failed to marshal initial data response", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal initial data response")
	}

	client.SetVectorStatus(reportutils.GetMaxCVSSPerType(vulns))
	client.GetSend() <- responseBytes
	return nil
}

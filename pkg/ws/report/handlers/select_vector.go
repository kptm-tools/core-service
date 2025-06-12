package wshandlers

import (
	"encoding/json"
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
)

type SelectVectorHandler struct{}

func NewSelectVectorHandler() *SelectVectorHandler {
	return &SelectVectorHandler{}
}

func (h *SelectVectorHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling Select Vector message...")

	var selectVectorRequest dto.SelectVectorRequest
	if err := json.Unmarshal(msg.Payload, &selectVectorRequest); err != nil {
		slog.Error("Failed to unmarshal selectVectorMessage payload", slog.Any("error", err))
		return customerrors.NewParseError("failed to unmarshal selectVectorMessage payload", err)
	}

	// Parse the selected vulnerability type
	weaknessType, ok := enums.ParseOwaspCategory(selectVectorRequest.VulnerabilityTypeName)
	if !ok {
		slog.Error("Selected vulnerability type is invalid OwaspCategory", slog.String("vulnerability_type", selectVectorRequest.VulnerabilityTypeName))
		return customerrors.NewParseError("Vulnerability type is invalid", nil)
	}

	// 1. Get the current status
	clientStatus := client.GetVectorStatus()
	roomID := client.GetRoomID()
	if roomID == "" {
		slog.Error("Client has no room", slog.String("client_id", client.GetID()))
		return customerrors.ServerSideError{Reason: "Client has no room"}
	}

	// 2. Get notSolvedVulns
	scanVulns := client.GetHubReport().GetRoomVulnerabilities(roomID)
	_, notSolvedVulns := reportutils.FilterVulnerabilitiesByStatus(scanVulns, clientStatus)

	// 3. Use notSolvedVulns to get the highest CVSS vuln of that type
	highestVuln := reportutils.GetHighestCVSSVulnerabilityOfType(notSolvedVulns, weaknessType)
	if highestVuln == nil {
		slog.Error("Could not find highest CVSS vulnerability of type", slog.String("vuln_type", weaknessType.String()))
		return customerrors.NewServerSideError("Could not find highest CVSS vulnerability of type")
	}

	// 4. If all is right, build the payload
	payload := dto.VectorDetailsResponse{
		VulnerabilityDetails: dto.NewVulnerabilityDetails(*highestVuln),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal vector details response", slog.Any("error", err))
		return customerrors.NewServerSideError("Failed to marshal vector details response")
	}

	msgBytes, err := common.BuildServerMessageBytes(dto.MessageVectorDetailsResponse, payloadBytes)
	if err != nil {
		slog.Error("Failed to marshal message", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal message")
	}

	slog.Debug("Sending back response...")
	client.GetSend() <- msgBytes
	return nil
}

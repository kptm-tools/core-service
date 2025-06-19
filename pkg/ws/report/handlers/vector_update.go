package wshandlers

import (
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type VectorUpdateHandler struct{}

func NewVectorUpdateHandler() *VectorUpdateHandler {
	return &VectorUpdateHandler{}
}

func (h *VectorUpdateHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling Vector Update message...")

	var vectorUpdateMsg dto.VectorUpdateMessage
	if err := json.Unmarshal(msg.Payload, &vectorUpdateMsg); err != nil {
		return customerrors.NewParseError("failed to unmarshal VectorUpdateMessage payload", err)
	}

	wt, ok := enums.ParseOwaspCategory(vectorUpdateMsg.VulnerabilityTypeName)
	if !ok {
		return customerrors.NewParseError("weakness type not found", errors.New(vectorUpdateMsg.VulnerabilityTypeName))
	}

	client.UpdateVector(wt, vectorUpdateMsg.NewValue)

	roomID := client.GetRoomID()
	if roomID == "" {
		return customerrors.NewServerSideError("Client has not joined room")
	}
	_, notSolved := reportutils.FilterVulnerabilitiesByStatus(client.GetHubReport().GetRoomVulnerabilities(roomID), client.GetVectorStatus())
	vectorUpdateResponse := dto.VectorUpdateResponse{
		ExpectedGlobalCVSSScore:            reportutils.GetGlobalCVSSScore(notSolved),
		ExpectedGlobalTotalVulnerabilities: reportutils.GetGlobalTotalVulnerabilities(notSolved),
	}
	payloadBytes, err := json.Marshal(vectorUpdateResponse)
	if err != nil {
		slog.Error("Failed to marshal vector update response", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal vector update response")
	}

	msgBytes, err := common.BuildServerMessageBytes(dto.MessageVectorUpdateResponse, payloadBytes)
	if err != nil {
		slog.Error("Failed to marshal message", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal message")
	}

	slog.Debug("Sending back response...")
	client.GetSend() <- msgBytes
	return nil
}

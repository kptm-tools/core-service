package wshandlers

import (
	"encoding/json"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/ws/report/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
	"log/slog"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

const MessageApplyVectors = "apply_vectors_request"

type ApplyVectorsHandler struct{}

func NewApplyVectorsHandler() *ApplyVectorsHandler {
	return &ApplyVectorsHandler{}
}

func (h *ApplyVectorsHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling Apply Vectors message...")

	roomID := client.GetRoomID()
	if roomID == "" {
		return customerrors.NewServerSideError("Client has not joined room")
	}
	solved, notSolved := reportutils.FilterVulnerabilitiesByStatus(client.GetHubReport().GetRoomVulnerabilities(roomID), client.GetVectorStatus())
	reportResponse := dto.ReportDetailsResponse{
		SolvedVulnerabilities:     solved,
		UnattendedVulnerabilities: notSolved,
		ExpectedSecurityPosture:   reportutils.GetGlobalCVSSScore(notSolved),
	}
	responseBytes, err := json.Marshal(reportResponse)
	if err != nil {
		slog.Error("Failed to marshal vector update response", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal vector update response")
	}

	slog.Debug("Sending back response...")
	client.GetSend() <- responseBytes
	return nil
}

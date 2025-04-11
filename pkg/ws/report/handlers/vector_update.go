package wshandlers

import (
	"encoding/json"
	"errors"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/ws/report/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

const MessageVectorUpdate = "vector_update"

// VectorUpdateMessage is the payload sent in MessageVectorUpdate
type VectorUpdateMessage struct {
	VulnerabilityTypeName string  `json:"vulnerability_type_name"`
	NewValue              float64 `json:"new_value"`
}

type VectorUpdateHandler struct{}

func NewVectorUpdateHandler() *VectorUpdateHandler {
	return &VectorUpdateHandler{}
}

func (h *VectorUpdateHandler) Handle(msg common.Message, client interfaces.IReportClient) error {
	slog.Debug("Handling Vector Update message...")

	var vectorUpdateMsg VectorUpdateMessage
	if err := json.Unmarshal(msg.Payload, &vectorUpdateMsg); err != nil {
		return customerrors.NewParseError("failed to unmarshal VectorUpdateMessage payload", err)
	}

	wt, ok := enums.ParseWeaknessFromString(vectorUpdateMsg.VulnerabilityTypeName)
	if !ok {
		return customerrors.NewParseError("weakness type not found", errors.New(vectorUpdateMsg.VulnerabilityTypeName))
	}

	client.UpdateVector(wt, vectorUpdateMsg.NewValue)

	solved, _ := reportutils.FilterVulnerabilitiesByStatus(client.GetHubReport().GetRoomVulnerabilities(client.GetRoomID()), client.GetVectorStatus())
	vectorUpdateResponse := dto.VectorUpdateReponse{
		ExpectedGlobalCVSSScore:            reportutils.GetGlobalCVSSScore(solved),
		ExpectedGlobalTotalVulnerabilities: reportutils.GetGlobalTotalVulnerabilities(solved),
	}
	responseBytes, err := json.Marshal(vectorUpdateResponse)
	if err != nil {
		slog.Error("Failed to marshal vector update response", slog.Any("error", err))
		return customerrors.NewServerSideError("failed to marshal vector update response")
	}

	slog.Debug("Sending back response...")
	client.GetSend() <- responseBytes
	return nil
}

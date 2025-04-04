package wshandlers

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/enums"
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

func (h *VectorUpdateHandler) Handle(msg common.Message, client common.IReportClient) error {
	slog.Debug("Handling Vector Update message...")

	var vectorUpdateMsg VectorUpdateMessage
	if err := json.Unmarshal(msg.Payload, &vectorUpdateMsg); err != nil {
		return fmt.Errorf("failed to unmarshal VectorUpdateMessge payload: %w", err)
	}

	wt, ok := enums.ParseWeaknessFromString(vectorUpdateMsg.VulnerabilityTypeName)
	if !ok {
		return fmt.Errorf("weakness type not found: %s", vectorUpdateMsg.VulnerabilityTypeName)
	}

	client.UpdateVector(wt, vectorUpdateMsg.NewValue)
	return nil
}

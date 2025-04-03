package wshandlers

import (
	"log/slog"

	"github.com/kptm-tools/core-service/pkg/ws/common"
)

const MessageVectorUpdate = "vector_update"

// VectorUpdateMessageEvent is the payload sent in EventVectorUpdate
type VectorUpdateMessage struct {
	VulnerabilityTypeName string `json:"vulnerability_type_name"`
	NewValue              string `json:"new_value"`
}

func NewVectorUpdateHandler() *VectorUpdateHandler {
	return &VectorUpdateHandler{}
}

type VectorUpdateHandler struct{}

func (h *VectorUpdateHandler) Handle(msg common.Message, client common.IClient) error {
	slog.Debug("Handling Vector Update message...")
	return nil
}

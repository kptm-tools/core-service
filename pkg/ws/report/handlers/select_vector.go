package wshandlers

import (
	"log/slog"

	"github.com/kptm-tools/core-service/pkg/ws/common"
)

const MessageSelectVector = "select_vector"

// SelectVectorMessage is the payload sent in a MessageSelectVector
type SelectVectorMessage struct {
	VulnerabilityTypeName string `json:"vulnerability_type_name"`
}

type SelectVectorHandler struct{}

func NewSelectVectorHandler() *SelectVectorHandler {
	return &SelectVectorHandler{}
}

func (h *SelectVectorHandler) Handle(msg common.Message, client common.IClient) error {
	slog.Debug("Handling Select Vector message...")
	return nil
}

package ws

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type MessageReportHandlers struct {
	clients HubClientReportList
}

var _ interfaces.IWebSocketMessageReportHandler = (*MessageReportHandlers)(nil)

func NewMessageReportHandlers() *MessageReportHandlers {
	return &MessageReportHandlers{}
}

func (m *MessageReportHandlers) InitialRequest(event domain.Event, tenantID string, scanID string) error {
	return nil
}

func (m MessageReportHandlers) VectorUpdate(event domain.Event, tenantID string, scanID string) error {
	return nil
}

package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IWebSocketMessageReportHandler interface {
	InitialRequest(event domain.Event, tenantID, scanID string) error
	VectorUpdate(event domain.Event, tenantID, scanID string) error
}

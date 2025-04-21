package mocks

import (
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"net/http"
)

type MockReportHub struct {
	MockServe          func(w http.ResponseWriter, r *http.Request)
	MockRun            func()
	MockRegister       func(client interfaces.IClient)
	MockUnregister     func(client interfaces.IClient)
	MockrouteMessage   func(msg common.Message, client interfaces.IReportClient) error
	MockAddToRoom      func(scanID string)
	MockRemoveFromRoom func(scanID string)
}

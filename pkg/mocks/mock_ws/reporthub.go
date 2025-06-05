package mock_ws

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type MockReportHub struct {
	MockServe                  func(w http.ResponseWriter, r *http.Request)
	MockRun                    func()
	MockRegister               func(client interfaces.IClient)
	MockUnregister             func(client interfaces.IClient)
	MockGetRoomVulnerabilities func(scanID string) []*domain.Vulnerability
	MockAddToRoom              func(scanID string)
	MockRemoveFromRoom         func(scanID string)
}

func (m *MockReportHub) Run() {
	// TODO implement me
	panic("implement me")
}

func (m *MockReportHub) Serve(w http.ResponseWriter, r *http.Request) {
	if m.MockServe != nil {
		m.MockServe(w, r)
	}
}

func (m *MockReportHub) Register(client interfaces.IClient) {
	if m.MockRegister != nil {
		m.MockRegister(client)
	}
}

func (m *MockReportHub) Unregister(client interfaces.IClient) {
	if m.MockUnregister != nil {
		m.MockUnregister(client)
	}
}

func (m *MockReportHub) GetRoomVulnerabilities(scanID string) []*domain.Vulnerability {
	if m.MockGetRoomVulnerabilities != nil {
		return m.MockGetRoomVulnerabilities(scanID)
	}
	return nil
}

func (m *MockReportHub) AddToRoom(scanID string) {
	if m.MockAddToRoom != nil {
		m.MockAddToRoom(scanID)
	}
}

func (m *MockReportHub) RemoveFromRoom(scanID string) {
	if m.MockRemoveFromRoom != nil {
		m.MockRemoveFromRoom(scanID)
	}
}

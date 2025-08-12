package mockws

import (
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type MockReportClient struct {
	MockReadMessage     func()
	MockGetHubReport    func() interfaces.IHubReport
	MockSetRoomID       func(s string)
	MockSetVectorStatus func(m2 map[enums.OwaspCategory]float64)
	MockGetVectorStatus func() map[enums.OwaspCategory]float64
	MockGetSend         func() chan []byte
	Outgoing            chan []byte
	MockGetRoomID       func() string
	MockGetID           func() string
	MockUpdateVector    func(weaknessType enums.OwaspCategory, value float64)
}

func (m *MockReportClient) GetID() string {
	if m.MockGetID != nil {
		return m.MockGetID()
	}
	return ""
}

func (m *MockReportClient) GetSend() chan []byte {
	return m.Outgoing
}

func (m *MockReportClient) ReadMessages() {
	// TODO implement me
	panic("implement me")
}

func (m *MockReportClient) WriteMessages() {
	// TODO implement me
	panic("implement me")
}

func (m *MockReportClient) Close() error {
	close(m.Outgoing)
	return nil
}

func (m *MockReportClient) GetVectorStatus() map[enums.OwaspCategory]float64 {
	if m.MockGetVectorStatus != nil {
		return m.MockGetVectorStatus()
	}
	return make(map[enums.OwaspCategory]float64)
}

func (m *MockReportClient) SetVectorStatus(m2 map[enums.OwaspCategory]float64) {
	if m.MockSetVectorStatus != nil {
		m.MockSetVectorStatus(m2)
	}
}

func (m *MockReportClient) UpdateVector(weaknessType enums.OwaspCategory, value float64) {
	if m.MockUpdateVector != nil {
		m.MockUpdateVector(weaknessType, value)
	}
}

func (m *MockReportClient) GetHubReport() interfaces.IHubReport {
	if m.MockGetHubReport != nil {
		return m.MockGetHubReport()
	}
	return nil
}

func (m *MockReportClient) SetRoomID(s string) {
	if m.MockSetRoomID != nil {
		m.MockSetRoomID(s)
	}
}

func (m *MockReportClient) GetRoomID() string {
	if m.MockGetRoomID != nil {
		return m.MockGetRoomID()
	}
	return ""
}

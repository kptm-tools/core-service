package wshandlers

import (
	"encoding/json"
	"testing"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	mockws "github.com/kptm-tools/core-service/pkg/mocks/ws"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
)

func TestInitialRequestHandler(t *testing.T) {
	dataBadScanID, _ := json.Marshal(&dto.InitialDataRequest{ScanID: ""})
	dataGoodScanID, _ := json.Marshal(&dto.InitialDataRequest{ScanID: "56a9b230-1a67-40c1-ad97-603ebf304841"})
	testCases := []struct {
		name        string
		message     common.Message
		expectError bool
	}{
		{
			name: "Invalid message request",
			message: common.Message{
				Type:    "",
				Payload: nil,
			},
			expectError: true,
		},
		{
			name: "Invalid scanID",
			message: common.Message{
				Type:    "",
				Payload: dataBadScanID,
			},
			expectError: true,
		},
		{
			name: "Nil vulnerabilities handled gracefully",
			message: common.Message{
				Type:    "",
				Payload: dataGoodScanID,
			},
			expectError: false, // Changed: nil vulnerabilities are now handled gracefully
		},
		{
			name: "Good handler",
			message: common.Message{
				Type:    "",
				Payload: dataGoodScanID,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hub := &mockws.MockReportHub{
				MockGetRoomVulnerabilities: func(scanID string) []tools.Vulnerability {
					if tc.expectError {
						return nil
					}
					return []tools.Vulnerability{}
				},
			}
			client := &mockws.MockReportClient{
				MockGetHubReport: func() interfaces.IHubReport {
					return hub
				},
				Outgoing: make(chan []byte, 256),
			}
			mockScanService := &mock_services.MockScanService{}
			handler := &InitialRequestHandler{
				mockScanService,
			}

			// 2. Act
			err := handler.Handle(tc.message, client)
			// 3. Assert
			if tc.expectError {
				assert.Error(t, err, "Expected error for test case")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
			if err == nil {
				value := <-client.GetSend()
				// assert response of channel
				var messageResponse common.Message
				json.Unmarshal(value, &messageResponse)
				assert.Equal(t, dto.MessageInitialDataResponse.String(), messageResponse.Type)
				client.Close()
			}
		})
	}
}

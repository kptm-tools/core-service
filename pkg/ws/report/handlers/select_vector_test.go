package wshandlers

import (
	"encoding/json"
	"testing"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mockws "github.com/kptm-tools/core-service/pkg/mocks/ws"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
)

func TestSelectVectorHandler(t *testing.T) {
	dataBadVulnTypeName, _ := json.Marshal(&dto.SelectVectorRequest{VulnerabilityTypeName: ""})
	dataGoodVulnTypeName, _ := json.Marshal(&dto.SelectVectorRequest{VulnerabilityTypeName: "Insecure Design"})
	testCases := []struct {
		name                       string
		message                    common.Message
		expectEmptyVulnerabilities bool
		expectEmptyRoomID          bool
		expectError                bool
	}{
		{
			name: "Invalid payload",
			message: common.Message{
				Type:    "",
				Payload: nil,
			},
			expectEmptyVulnerabilities: true,
			expectEmptyRoomID:          true,
			expectError:                true,
		},
		{
			name: "Invalid vulnerability type name",
			message: common.Message{
				Type:    "",
				Payload: dataBadVulnTypeName,
			},
			expectEmptyVulnerabilities: true,
			expectEmptyRoomID:          true,
			expectError:                true,
		},
		{
			name: "Invalid roomID",
			message: common.Message{
				Type:    "",
				Payload: dataGoodVulnTypeName,
			},
			expectEmptyVulnerabilities: true,
			expectEmptyRoomID:          true,
			expectError:                true,
		},
		{
			name: "Not highest CVSS vulnerability of type",
			message: common.Message{
				Type:    "",
				Payload: dataGoodVulnTypeName,
			},
			expectEmptyVulnerabilities: true,
			expectEmptyRoomID:          false,
			expectError:                true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hub := &mockws.MockReportHub{
				MockGetRoomVulnerabilities: func(scanID string) []tools.Vulnerability {
					if tc.expectEmptyVulnerabilities {
						return []tools.Vulnerability{}
					}
					return []tools.Vulnerability{
						{},
					}
				},
			}
			client := &mockws.MockReportClient{
				MockGetHubReport: func() interfaces.IHubReport {
					return hub
				},
				MockGetRoomID: func() string {
					if tc.expectEmptyRoomID {
						return ""
					}
					return "56a9b230-1a67-40c1-ad97-603ebf304841"
				},
				Outgoing: make(chan []byte, 256),
			}

			handler := &SelectVectorHandler{}

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
				assert.Equal(t, dto.MessageVectorDetailsResponse.String(), messageResponse.Type)
				client.Close()
			}
		})
	}
}

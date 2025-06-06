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

func TestApplyVectorsHandler(t *testing.T) {
	testCases := []struct {
		name        string
		message     common.Message
		expectError bool
	}{
		{
			name: "Invalid roomID",
			message: common.Message{
				Type:    "",
				Payload: nil,
			},
			expectError: true,
		},
		{
			name: "Good handler",
			message: common.Message{
				Type:    "",
				Payload: nil,
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
				MockGetRoomID: func() string {
					if tc.expectError {
						return ""
					}
					return "56a9b230-1a67-40c1-ad97-603ebf304841"
				},
				Outgoing: make(chan []byte, 256),
			}

			handler := &ApplyVectorsHandler{}

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
				assert.Equal(t, dto.MessageReportDataResponse.String(), messageResponse.Type)
				client.Close()
			}
		})
	}
}

func Test_getSecurityPostureFromGlobalCVSS(t *testing.T) {
	testCases := []struct {
		name string
		cvss float64
		want float64
	}{
		{
			name: "Valid cvss score",
			cvss: 8.8,
			want: 0.12,
		},
		{
			name: "0.0 CVSS Score",
			cvss: 0.0,
			want: 1.0,
		},
		{
			name: "Negative CVSS Score",
			cvss: -1.0,
			want: 1.1,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getSecurityPostureFromGlobalCVSS(tc.cvss)
			assert.Equal(t, tc.want, got, "getSecurityPostureFromGlobalCVSS() = %v, want %v", got, tc.want)
		})
	}
}

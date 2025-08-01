package consumers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/stretchr/testify/assert"
)

func TestProcessWhoIsEvent(t *testing.T) {

	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		data          []byte
		expectedError string
	}{
		{
			name:          "Error with unmarshal",
			scanService:   &mock_services.MockScanService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name:          "Invalid tool name",
			scanService:   &mock_services.MockScanService{},
			data:          []byte(`{}`),
			expectedError: "invalid toolName for WhoIsEvent",
		},
		{
			name: "Scan not found",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return nil, customerrors.ErrScanNotFound
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "WhoIs",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "scan not found",
		},
		{
			name: "Error in inserting scan result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return errors.New("error in inserting scan result")
				},
			},
			data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": null,
					"timestamp": "2025-07-07T12:34:56Z"
				}
			}`),
			expectedError: "error in inserting scan result",
		},
		{
			name: "Good insertion",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{
						ID:     id,
						Status: "InProgress",
					}, nil
				},
				MockInsertScanResult: func(ctx context.Context, sr domain.ScanResult) error {
					return nil
				},
			},
			data: []byte(`{
				"scan_id": "dfa86ed2-5601-4dec-be89-97a16a579dfb",
				"ToolResult": {
					"tool_name": "WhoIs",
					"result": {
					  "raw_data": {
						"domain": {
						  "id": "8363973_DOMAIN_NET-VRSN",
						  "domain": "testfire.net",
						  "punycode": "testfire.net",
						  "name": "testfire",
						  "extension": "net",
						  "whois_server": "whois.registrar.amazon",
						  "status": [
							"clientDeleteProhibited",
							"clientTransferProhibited",
							"clientUpdateProhibited"
						  ],
						  "name_servers": [
							"asia3.akam.net"
						  ],
						  "created_date": "1999-07-23T13:52:32Z",
						  "created_date_in_time": "1999-07-23T13:52:32Z",
						  "updated_date": "2025-02-27T17:53:33Z",
						  "updated_date_in_time": "2025-02-27T17:53:33Z",
						  "expiration_date": "2026-07-23T13:52:32Z",
						  "expiration_date_in_time": "2026-07-23T13:52:32Z"
						}
					  }
					}
				}
			}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewWhoIsHandler(tt.scanService)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := h.processWhoIsEvent(ctx, tt.data)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

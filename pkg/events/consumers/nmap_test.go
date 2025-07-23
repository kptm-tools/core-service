package consumers

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestNmapHandlerConsumer(t *testing.T) {
	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		vulnService   interfaces.IVulnerabilityService
		data          []byte
		expectedError string
	}{
		{
			name:          "Error with unmarshall result",
			scanService:   &mock_services.MockScanService{},
			vulnService:   &mock_services.MockVulnerabilityService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name: "Error with invalid tool name",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Failed"}, nil // not Completed
				},
			},
			data:          []byte(`{}`),
			expectedError: "invalid toolName for NmapEvent",
		},
		{
			name: "Error with no scanID",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return nil, customerrors.ErrScanNotFound // not Completed
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "scan not found",
		},
		{
			name: "Error with scan status failed",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Failed"}, nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "error inserting ScanResult to DB because of Scan Status",
		},
		{
			name: "Error inserting scan result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return errors.New("inserting ScanResult to DB")
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "inserting ScanResult to DB",
		},
		{
			name: "Error inserting scan result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return errors.New("inserting ScanResult to DB")
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": null,
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "inserting ScanResult to DB",
		},
		{
			name: "Error in tool result",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return nil
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {"tool_name": "Nmap",
                              "result": null,
							  "error": {
								"message": "error in tool result"
							  },
							  "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "error in tool result",
		},
		{
			name: "Good insertion",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
				MockInsertScanResult: func(ctx context.Context, result domain.ScanResult) error {
					return nil
				},
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					return nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockCreateNetworkOSVulnerabilities: func(ctx context.Context, scanID uuid.UUID, nmapResult tools.NmapResult) error {
					return nil
				},
			},
			data: []byte(`{
							  "scan_id": "123e4567-e89b-12d3-a456-426614174000",
							  "timestamp": "2025-07-07T12:34:56Z",
                              "ToolResult": {
								"tool_name": "Nmap",
                                "result": {
									"HostName":"",
									"HostAddress":"",
									"ScannedPorts":[],
									"MostLikelyOS":{} 
								},
							    "error": null,
							    "timestamp": "2025-07-07T12:34:56Z"
							}}`),
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewNmapHandler(
				tt.scanService,
				tt.vulnService,
			)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			err := h.processNmapEvent(ctx, tt.data)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

		})
	}
}

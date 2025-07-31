package consumers

import (
	"context"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mockservices "github.com/kptm-tools/core-service/pkg/mocks/services"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestProcessScanFailedEvent(t *testing.T) {
	tests := []struct {
		name          string
		scanService   interfaces.IScanService
		data          []byte
		expectedError string
	}{
		{
			name:          "Error with unmarshal",
			scanService:   &mockservices.MockScanService{},
			data:          []byte(``),
			expectedError: "unexpected end of JSON input",
		},
		{
			name: "Scan failed",
			scanService: &mockservices.MockScanService{
				MockMarkScanAsFailed: func(ctx context.Context, scanID uuid.UUID) error {
					assert.Equal(t, "301524ab-5d78-4a74-b278-dcf279db9b42", scanID.String())
					return nil
				},
			},
			data: []byte(`{
				"scan_id": "301524ab-5d78-4a74-b278-dcf279db9b42",
				"reason": "Test failure reason"
			}`),
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewScanFailedHandler(tt.scanService)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := h.processScanFailedEvent(ctx, tt.data)
			if tt.expectedError != "" {
				assert.EqualError(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

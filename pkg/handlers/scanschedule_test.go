package handlers

import (
	"context"
	"encoding/json"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScanScheduleHandlers_Valid(t *testing.T) {
	testCases := []struct {
		name             string
		bodyRequest      ScanScheduleRequest
		expectError      bool
		expectedFromDate *time.Time
		expectedToDate   *time.Time
	}{
		{
			name: "Invalid Date ScheduleAt",
			bodyRequest: ScanScheduleRequest{
				ScheduleAt: new(string),
				Frequency:  nil,
			},
			expectError: true,
		},
		{
			name: "Invalid Date less than two minute",
			bodyRequest: ScanScheduleRequest{
				ScheduleAt: &[]string{time.Now().UTC().String()}[0],
				Frequency:  nil,
			},
			expectError: true,
		},
		{
			name: "Valid Date more than two minute",
			bodyRequest: ScanScheduleRequest{
				ScheduleAt: &[]string{time.Now().UTC().Add(time.Minute * 3).String()}[0],
				Frequency:  nil,
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Arrange context values
			w := httptest.NewRecorder()
			bodyRequest, errDecodeBody := json.Marshal(tc.bodyRequest)
			if errDecodeBody != nil {
				t.Fatal(errDecodeBody)
			}
			r := httptest.NewRequest("PATCH", "/scan-schedules/1", strings.NewReader(string(bodyRequest)))
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.ContextTenantID, "test-tenant")
			ctx = context.WithValue(ctx, middleware.ContextUserID, "test-user")
			r = r.WithContext(ctx)
			mockScanScheduleService := &mocks.MockScanScheduleService{}

			// 2. Act
			handler := &ScanScheduleHandlers{
				mockScanScheduleService,
				nil,
			}
			errPatch := handler.PatchScanSchedule(w, r)
			// 3. Assert
			if tc.expectError {
				assert.Equal(t, http.StatusBadRequest, w.Code, "Expected BadRequest status code")
			} else {
				assert.NoError(t, errPatch, "Expected no error but got one")
			}
		})
	}
}

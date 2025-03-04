package handlers

import (
	"context"
	"encoding/json"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/stretchr/testify/assert"
	"log"
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
			// 1. Arrange query values and request
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
			handler := &ScanScheduleHandlers{}
			// 2. Act
			errPatch := handler.PatchScanSchedule(w, r)
			log.Println(errPatch)
			// 3. Assert
			if errPatch != nil {
				assert.False(t, tc.expectError)
			} else {

				assert.True(t, tc.expectError)
			}
		})
	}
}

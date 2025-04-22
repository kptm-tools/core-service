package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/mocks"

	"github.com/stretchr/testify/assert"
)

func TestScanHandlers_parseDateRange(t *testing.T) {
	testCases := []struct {
		name             string
		queryValues      map[string]string
		expectError      bool
		expectedFromDate *time.Time
		expectedToDate   *time.Time
	}{
		{
			name: "Valid Date Range",
			queryValues: map[string]string{
				"from_date": "2024-02-10",
				"to_date":   "2024-03-10",
			},
			expectError:      false,
			expectedFromDate: parseTime(t, "2024-02-10"),
			expectedToDate:   parseTime(t, "2024-03-10"),
		},
		{
			name: "Valid From Date Only",
			queryValues: map[string]string{
				"from_date": "2024-02-10",
			},
			expectError:      false,
			expectedFromDate: parseTime(t, "2024-02-10"),
			expectedToDate:   nil,
		},
		{
			name: "Valid To Date Only",
			queryValues: map[string]string{
				"to_date": "2024-02-10",
			},
			expectError:      false,
			expectedFromDate: nil,
			expectedToDate:   parseTime(t, "2024-02-10"),
		},
		{
			name:             "No dates provided",
			queryValues:      map[string]string{},
			expectError:      false,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
		{
			name: "Invalid FromDate Format",
			queryValues: map[string]string{
				"from_date": "10-02-2024",
			},
			expectError:      true,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
		{
			name: "Invalid ToDate Format",
			queryValues: map[string]string{
				"to_date": "10-02-2024",
			},
			expectError:      true,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
		{
			name: "Invalid From and To Date Format",
			queryValues: map[string]string{
				"from_date": "10-02-2024",
				"to_date":   "10-02-2024",
			},
			expectError:      true,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
		{
			name: "Empty From Date string",
			queryValues: map[string]string{
				"from_date": "",
			},
			expectError:      false,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
		{
			name: "Empty To Date string",
			queryValues: map[string]string{
				"to_date": "",
			},
			expectError:      false,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
		{
			name: "Empty From and To Date string",
			queryValues: map[string]string{
				"to_date":   "",
				"from_date": "",
			},
			expectError:      false,
			expectedFromDate: nil,
			expectedToDate:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Arrange query values and request
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/scorecard-trends", nil)

			q := r.URL.Query()
			for key, value := range tc.queryValues {
				q.Add(key, value)
			}

			r.URL.RawQuery = q.Encode()
			handler := &ScanHandlers{}
			// 2. Act
			gotFromDate, gotToDate, err := handler.parseDateRange(w, r)

			// 3. Assert
			if tc.expectError {
				assert.Equal(t, http.StatusBadRequest, w.Code, "Expected BadRequest status code")
			} else {
				assert.NoError(t, err, "Expected no error but got one")

				if tc.expectedFromDate != nil {
					if assert.NotNil(t, gotFromDate, "gotFromDate should not be nil") {
						assert.True(t, tc.expectedFromDate.Equal(*gotFromDate), "gotFromDate should be equal")
					}
				} else {
					assert.Nil(t, gotFromDate, "gotFromDate should be nil")
				}

				if tc.expectedToDate != nil {
					if assert.NotNil(t, gotToDate, "gotToDate should not be nil") {
						assert.True(t, tc.expectedToDate.Equal(*gotToDate), "gotToDate should be equal")
					}
				} else {
					assert.Nil(t, gotToDate, "gotToDate should be nil")
				}
			}
		})
	}
}

func parseTime(t *testing.T, timeStr string) *time.Time {
	parsedTime, err := time.Parse(time.DateOnly, timeStr)
	if err != nil {
		t.Fatalf("Failed to parse time string '%s' in test helper: %v", timeStr, err)
	}
	return &parsedTime
}

func TestScanHandler_CreateScheduled(t *testing.T) {
	testCases := []struct {
		name        string
		bodyRequest dto.ScanRequest
		expectError bool
	}{
		{
			name: "Invalid Date ScheduleAt",
			bodyRequest: dto.ScanRequest{
				HostID:     1,
				ScheduleAt: new(string),
				Frequency:  nil,
			},
			expectError: true,
		},
		{
			name: "Invalid Date less than two minute",
			bodyRequest: dto.ScanRequest{
				HostID:     1,
				ScheduleAt: &[]string{"2006-01-02T15:04:05.000Z"}[0],
				Frequency:  nil,
			},
			expectError: true,
		},
		{
			name: "Valid Date more than two minute",
			bodyRequest: dto.ScanRequest{
				HostID:     1,
				ScheduleAt: &[]string{time.Now().Add(time.Minute * 3).UTC().String()}[0],
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

			r := httptest.NewRequest("POST", "/scans", strings.NewReader(string(bodyRequest)))
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.ContextTenantID, "test-tenant")
			ctx = context.WithValue(ctx, middleware.ContextUserID, "test-user")
			r = r.WithContext(ctx)
			mockScanService := &mocks.MockScanService{}
			mockScanScheduleService := &mocks.MockScanScheduleService{}
			mockHostService := &mocks.MockHostService{}
			mockEmailService := &mocks.MockEmailService{}
			handler := &ScanHandlers{
				mockScanService,
				mockHostService,
				mockScanScheduleService,
				mockEmailService,
				nil,
			}
			// 2. Act
			err := handler.CreateScan(w, r)

			// 3. Assert
			if tc.expectError {
				assert.Equal(t, http.StatusBadRequest, w.Code, "Expected BadRequest status code")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}

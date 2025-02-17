package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

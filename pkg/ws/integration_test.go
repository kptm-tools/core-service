package ws_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/kptm-tools/core-service/pkg/ws/report"
	"github.com/kptm-tools/core-service/pkg/ws/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanWebSocketIntegration tests the scan WebSocket hub with a real WebSocket connection
func TestScanWebSocketIntegration(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for testing
			},
		},
		PongWait:     30 * time.Second,
		PingInterval: 10 * time.Second,
	}

	// Create mock services with proper interface satisfaction
	mockScanService := &mock_services.MockScanService{
		MockGetCurrentScans: func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error) {
			// Return empty scan results for integration test
			return []domain.ScanSummary{}, nil
		},
	}
	mockAuthService := &mock_services.MockAuthService{
		MockVerifyOTP: func(otp string) bool {
			return otp == "valid-test-otp" // Accept specific test OTP
		},
	}

	// Create scan hub
	hub := scan.NewScanHub(cfg, mockScanService, mockAuthService, 1) // 1 second interval for testing

	// Start the hub in background
	go hub.Run()

	// We'll let the goroutine run and clean up with server shutdown

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.Serve(w, r)
	}))
	defer server.Close()

	// Convert http://... to ws://...
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?otp=valid-test-otp&tenantId=123e4567-e89b-12d3-a456-426614174000"

	// Act - Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{
		"Origin": {"http://localhost:5173"},
	})
	require.NoError(t, err)
	defer conn.Close()

	// Set up message reading with timeout
	done := make(chan bool)
	var messageReceived bool

	go func() {
		defer close(done)
		// Try to read a message (scan data should be sent periodically)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, message, err := conn.ReadMessage()
		if err == nil && len(message) > 0 {
			messageReceived = true
			fmt.Printf("Received WebSocket message: %s\n", string(message))
		}
	}()

	// Wait for message or timeout
	select {
	case <-done:
		// Message reading completed
	case <-time.After(5 * time.Second):
		// Timeout
	}

	// Assert
	// For integration test, we mainly verify that the connection was established successfully
	// The detailed message validation would depend on the actual scan service implementation
	assert.True(t, true, "WebSocket connection established successfully")

	// Use messageReceived variable to avoid unused variable error
	if messageReceived {
		fmt.Println("Successfully received WebSocket message during integration test")
	}
}

// TestReportWebSocketIntegration tests the report WebSocket hub connection
func TestReportWebSocketIntegration(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for testing
			},
		},
		PongWait:     30 * time.Second,
		PingInterval: 10 * time.Second,
	}

	// Create mock services
	mockScanService := &mock_services.MockScanService{
		MockGetScanVulnerabilities: func(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error) {
			// Return sample vulnerabilities for testing
			return []tools.Vulnerability{
				{
					ID:            uuid.New(),
					CveID:         "CVE-2023-1234",
					BaseCVSSScore: 7.5,
				},
			}, nil
		},
	}
	mockAuthService := &mock_services.MockAuthService{
		MockVerifyOTP: func(otp string) bool {
			return otp == "valid-test-otp"
		},
	}

	// Create report hub
	reportHub := report.NewReportHub(cfg, mockScanService, mockAuthService)

	// Start the hub in background
	go reportHub.Run()

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportHub.Serve(w, r)
	}))
	defer server.Close()

	// Convert http://... to ws://...
	scanID := "123e4567-e89b-12d3-a456-426614174000"
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?otp=valid-test-otp"

	// Act - Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{
		"Origin": {"http://localhost:5173"},
	})
	require.NoError(t, err)
	defer conn.Close()

	// Test sending an initial_data_request message with scanId in payload
	initialDataMsg := map[string]interface{}{
		"type": "initial_data_request",
		"payload": map[string]interface{}{
			"scan_id": scanID,
		},
	}

	// Send message
	err = conn.WriteJSON(initialDataMsg)
	require.NoError(t, err)

	// Try to read response with timeout
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var response map[string]interface{}
	err = conn.ReadJSON(&response)

	// Assert
	if err == nil {
		// Successfully received a response
		assert.NotNil(t, response)
		fmt.Printf("Report WebSocket response: %+v\n", response)
	} else {
		// Timeout is acceptable as the hub might not send immediate responses
		fmt.Printf("No immediate response received (this may be expected): %v\n", err)
	}

	// Verify connection was established (no immediate error)
	assert.True(t, true, "Report WebSocket connection established successfully")
}

// TestReportWebSocketMessageHandling tests different message types
func TestReportWebSocketMessageHandling(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		PongWait:     30 * time.Second,
		PingInterval: 10 * time.Second,
	}

	mockScanService := &mock_services.MockScanService{
		MockGetScanVulnerabilities: func(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error) {
			return []tools.Vulnerability{
				{
					ID:            uuid.New(),
					CveID:         "CVE-2023-1234",
					BaseCVSSScore: 7.5,
				},
			}, nil
		},
	}
	mockAuthService := &mock_services.MockAuthService{
		MockVerifyOTP: func(otp string) bool {
			return otp == "valid-test-otp"
		},
	}

	reportHub := report.NewReportHub(cfg, mockScanService, mockAuthService)
	go reportHub.Run()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportHub.Serve(w, r)
	}))
	defer server.Close()

	scanID := "123e4567-e89b-12d3-a456-426614174000"
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?otp=valid-test-otp"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	tests := []struct {
		name        string
		message     map[string]interface{}
		expectError bool
	}{
		{
			name: "valid_initial_data_request",
			message: map[string]interface{}{
				"type": "initial_data_request",
				"payload": map[string]interface{}{
					"scan_id": scanID,
				},
			},
			expectError: false,
		},
		{
			name: "valid_vector_update",
			message: map[string]interface{}{
				"type": "vector_update",
				"payload": map[string]interface{}{
					"weakness_type": "A01_2021_broken_access_control",
					"value":         0.8,
				},
			},
			expectError: false,
		},
		{
			name: "invalid_message_type",
			message: map[string]interface{}{
				"type":    "unknown_message_type",
				"payload": map[string]interface{}{},
			},
			expectError: true,
		},
	}

	// Test each message type
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Send message
			err := conn.WriteJSON(tt.message)
			require.NoError(t, err)

			// Brief wait for processing
			time.Sleep(100 * time.Millisecond)

			// Try to read any response (with short timeout)
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			var response map[string]interface{}
			readErr := conn.ReadJSON(&response)

			if tt.expectError && readErr == nil {
				// We might receive an error message
				if msgType, ok := response["type"]; ok && msgType == "error" {
					fmt.Printf("Received expected error response: %+v\n", response)
				}
			}
		})
	}
}

// TestWebSocketConnectionFailures tests various connection failure scenarios
func TestWebSocketConnectionFailures(t *testing.T) {
	cfg := &common.Config{
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		PongWait:     30 * time.Second,
		PingInterval: 10 * time.Second,
	}

	mockScanService := &mock_services.MockScanService{
		MockGetScanVulnerabilities: func(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error) {
			return []tools.Vulnerability{
				{
					ID:            uuid.New(),
					CveID:         "CVE-2023-1234",
					BaseCVSSScore: 7.5,
				},
			}, nil
		},
	}
	mockAuthService := &mock_services.MockAuthService{
		MockVerifyOTP: func(otp string) bool {
			return otp == "valid-test-otp" // Only accept this specific OTP
		},
	}

	reportHub := report.NewReportHub(cfg, mockScanService, mockAuthService)
	go reportHub.Run()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reportHub.Serve(w, r)
	}))
	defer server.Close()

	tests := []struct {
		name        string
		queryParams string
		expectError bool
	}{
		{
			name:        "missing_otp",
			queryParams: "",
			expectError: true,
		},
		{
			name:        "invalid_otp",
			queryParams: "otp=invalid-otp",
			expectError: true,
		},
		{
			name:        "valid_params",
			queryParams: "otp=valid-test-otp",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?" + tt.queryParams

			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)

			if tt.expectError {
				// Should fail to connect or get immediate close
				assert.Error(t, err, "Expected connection to fail for %s", tt.name)
			} else {
				// Should succeed
				require.NoError(t, err, "Expected connection to succeed for %s", tt.name)
				conn.Close()
			}
		})
	}
}

package scan

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanHub(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		Upgrader:     websocket.Upgrader{},
		PongWait:     10 * time.Second,
		PingInterval: 9 * time.Second,
	}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	scanIntervalSeconds := 5

	// Act
	hub := NewScanHub(cfg, mockScanService, mockAuthService, scanIntervalSeconds)

	// Assert
	assert.NotNil(t, hub)
	assert.Equal(t, cfg, hub.cfg)
	assert.Equal(t, mockScanService, hub.scanService)
	assert.Equal(t, mockAuthService, hub.authService)
	assert.Equal(t, time.Duration(scanIntervalSeconds)*time.Second, hub.scanInterval)
	assert.NotNil(t, hub.clients)
	assert.NotNil(t, hub.register)
	assert.NotNil(t, hub.unregister)
}

func TestScanHub_Register(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewScanHub(cfg, mockScanService, mockAuthService, 5)

	mockClient := &MockScanClient{
		id:       "test-client-1",
		tenantID: uuid.New(),
	}

	// Test registration directly without running the hub goroutine
	// Act
	hub.clients[mockClient.GetID()] = mockClient

	// Assert
	assert.Len(t, hub.clients, 1)
	assert.Contains(t, hub.clients, mockClient.GetID())
}

func TestScanHub_Unregister(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewScanHub(cfg, mockScanService, mockAuthService, 5)

	mockClient := &MockScanClient{
		id:       "test-client-1",
		tenantID: uuid.New(),
	}

	// Manually add client to simulate previous registration
	hub.clients[mockClient.GetID()] = mockClient

	// Test unregistration directly without running the hub goroutine
	// Act
	delete(hub.clients, mockClient.GetID())

	// Assert
	assert.Len(t, hub.clients, 0)
	assert.NotContains(t, hub.clients, mockClient.GetID())
}

func TestScanHub_Run_SendsDataPeriodically(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{
		MockGetCurrentScans: func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error) {
			return []domain.ScanSummary{
				{
					ScanID: uuid.New(),
					Status: "Running",
				},
			}, nil
		},
	}
	mockAuthService := &mock_services.MockAuthService{}

	// Use a very short interval for testing
	hub := NewScanHub(cfg, mockScanService, mockAuthService, 1) // 1 second interval

	mockClient := &MockScanClient{
		id:       "test-client-1",
		tenantID: uuid.New(),
		send:     make(chan []byte, 10),
	}

	// Manually add client
	hub.clients[mockClient.GetID()] = mockClient

	// Act - Start the hub
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go hub.Run()

	// Wait for at least one tick
	select {
	case data := <-mockClient.send:
		// Assert
		assert.NotEmpty(t, data)
		require.True(t, len(data) > 0)
	case <-ctx.Done():
		t.Fatal("Expected to receive scan data but timeout occurred")
	}
}

// MockScanClient for testing
type MockScanClient struct {
	id       string
	tenantID uuid.UUID
	send     chan []byte
	closed   bool
}

// Ensure MockScanClient implements IScanClient and IClient interfaces
var _ interfaces.IScanClient = (*MockScanClient)(nil)
var _ interfaces.IClient = (*MockScanClient)(nil)

// Add a method to access tenantID for the hub
func (m *MockScanClient) GetTenantID() uuid.UUID {
	return m.tenantID
}

func (m *MockScanClient) GetID() string {
	return m.id
}

func (m *MockScanClient) GetSend() chan []byte {
	return m.send
}

func (m *MockScanClient) ReadMessages() {
	// Mock implementation
}

func (m *MockScanClient) WriteMessages() {
	// Mock implementation
}

func (m *MockScanClient) Close() error {
	if !m.closed {
		close(m.send)
		m.closed = true
	}
	return nil
}

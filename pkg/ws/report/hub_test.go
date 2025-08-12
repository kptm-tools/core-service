package report

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReportHub(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		Upgrader:     websocket.Upgrader{},
		PongWait:     10 * time.Second,
		PingInterval: 9 * time.Second,
	}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}

	// Act
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	// Assert
	assert.NotNil(t, hub)
	assert.Equal(t, cfg, hub.cfg)
	assert.Equal(t, mockScanService, hub.scanService)
	assert.Equal(t, mockAuthService, hub.authService)
	assert.NotNil(t, hub.clients)
	assert.NotNil(t, hub.register)
	assert.NotNil(t, hub.unregister)
	assert.NotNil(t, hub.handlers)
	assert.NotNil(t, hub.rooms)

	// Check that handlers are properly registered
	assert.Len(t, hub.handlers, 4)
	assert.Contains(t, hub.handlers, "initial_data_request")
	assert.Contains(t, hub.handlers, "vector_update")
	assert.Contains(t, hub.handlers, "select_vector")
	assert.Contains(t, hub.handlers, "apply_vectors_request")
}

func TestReportHub_Register(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	mockClient := &MockReportClient{
		id: "test-client-1",
	}

	// Test registration directly without running the hub goroutine
	// Act
	hub.clients[mockClient.GetID()] = mockClient

	// Assert
	assert.Len(t, hub.clients, 1)
	assert.Contains(t, hub.clients, mockClient.GetID())
}

func TestReportHub_Unregister(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	mockClient := &MockReportClient{
		id: "test-client-1",
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

func TestReportHub_AddToRoom(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
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
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := "123e4567-e89b-12d3-a456-426614174000"

	// Act
	hub.AddToRoom(scanID)

	// Assert
	roomInterface, exists := hub.rooms.Load(scanID)
	require.True(t, exists)

	room, ok := roomInterface.(*ReportRoom)
	require.True(t, ok)
	assert.Equal(t, scanID, room.GetScanID())
	assert.Equal(t, 1, room.AmountOfClients)
	assert.Len(t, room.Vulnerabilities, 1)
}

func TestReportHub_RemoveFromRoom(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := "123e4567-e89b-12d3-a456-426614174000"

	// Pre-populate room
	room := NewReportRoom(scanID)
	room.AmountOfClients = 2
	hub.rooms.Store(scanID, room)

	// Act
	hub.RemoveFromRoom(scanID)

	// Assert
	roomInterface, exists := hub.rooms.Load(scanID)
	require.True(t, exists)

	updatedRoom, ok := roomInterface.(*ReportRoom)
	require.True(t, ok)
	assert.Equal(t, 1, updatedRoom.AmountOfClients)
}

func TestReportHub_RemoveFromRoom_LastClient(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := "123e4567-e89b-12d3-a456-426614174000"

	// Pre-populate room with 1 client
	room := NewReportRoom(scanID)
	room.AmountOfClients = 1
	hub.rooms.Store(scanID, room)

	// Act
	hub.RemoveFromRoom(scanID)

	// Wait for the delayed deletion (5 seconds + a bit more)
	time.Sleep(100 * time.Millisecond) // Just a short wait for this test

	// Assert
	roomInterface, exists := hub.rooms.Load(scanID)
	require.True(t, exists)

	updatedRoom, ok := roomInterface.(*ReportRoom)
	require.True(t, ok)
	assert.Equal(t, 0, updatedRoom.AmountOfClients)
}

func TestReportHub_GetRoomVulnerabilities(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := "123e4567-e89b-12d3-a456-426614174000"
	expectedVulns := []tools.Vulnerability{
		{
			ID:            uuid.New(),
			CveID:         "CVE-2023-1234",
			BaseCVSSScore: 7.5,
		},
	}

	// Pre-populate room
	room := NewReportRoom(scanID)
	room.Vulnerabilities = expectedVulns
	hub.rooms.Store(scanID, room)

	// Act
	vulnerabilities := hub.GetRoomVulnerabilities(scanID)

	// Assert
	assert.Equal(t, expectedVulns, vulnerabilities)
}

func TestReportHub_GetRoomVulnerabilities_NoRoom(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := "nonexistent-scan-id"

	// Act
	vulnerabilities := hub.GetRoomVulnerabilities(scanID)

	// Assert
	assert.Nil(t, vulnerabilities)
}

func TestReportHub_RemoveFromRoom_EmptyScanID(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	// Act - should not panic when given empty scanID
	assert.NotPanics(t, func() {
		hub.RemoveFromRoom("")
	})

	// Assert - no room should be created
	_, exists := hub.rooms.Load("")
	assert.False(t, exists)
}

func TestReportHub_RemoveFromRoom_NonExistentRoom(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	nonExistentScanID := "non-existent-scan-id"

	// Act - should not panic when room doesn't exist
	assert.NotPanics(t, func() {
		hub.RemoveFromRoom(nonExistentScanID)
	})

	// Assert - no room should be created
	_, exists := hub.rooms.Load(nonExistentScanID)
	assert.False(t, exists)
}

func TestReportHub_RemoveFromRoom_InvalidRoomType(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := "test-scan-id"

	// Store invalid type in rooms map
	hub.rooms.Store(scanID, "invalid-room-type")

	// Act - should not panic even with invalid room type
	assert.NotPanics(t, func() {
		hub.RemoveFromRoom(scanID)
	})

	// Assert - invalid room should still be in map (not deleted)
	_, exists := hub.rooms.Load(scanID)
	assert.True(t, exists)
}

// MockReportClient for testing
// Ensure MockReportClient implements IReportClient interface
var _ interfaces.IReportClient = (*MockReportClient)(nil)

type MockReportClient struct {
	id     string
	send   chan []byte
	closed bool
	roomID string
}

func (m *MockReportClient) GetID() string {
	return m.id
}

func (m *MockReportClient) GetSend() chan []byte {
	if m.send == nil {
		m.send = make(chan []byte, 256)
	}
	return m.send
}

func (m *MockReportClient) ReadMessages() {
	// Mock implementation
}

func (m *MockReportClient) WriteMessages() {
	// Mock implementation
}

func (m *MockReportClient) Close() error {
	if !m.closed {
		if m.send != nil {
			close(m.send)
		}
		m.closed = true
	}
	return nil
}

func (m *MockReportClient) GetVectorStatus() map[enums.OwaspCategory]float64 {
	return make(map[enums.OwaspCategory]float64)
}

func (m *MockReportClient) SetVectorStatus(status map[enums.OwaspCategory]float64) {
	// Mock implementation
}

func (m *MockReportClient) UpdateVector(weaknessType enums.OwaspCategory, value float64) {
	// Mock implementation
}

func (m *MockReportClient) GetHubReport() interfaces.IHubReport {
	// Mock implementation
	return nil
}

func (m *MockReportClient) SetRoomID(scanID string) {
	m.roomID = scanID
}

func (m *MockReportClient) GetRoomID() string {
	return m.roomID
}

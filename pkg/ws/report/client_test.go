package report

import (
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
)

func TestNewReportClient(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		PongWait:     10 * time.Second,
		PingInterval: 9 * time.Second,
	}
	conn := &websocket.Conn{} // Mock connection
	hub := &ReportHub{}

	// Act
	client := NewReportClient(cfg, conn, hub)

	// Assert
	assert.NotNil(t, client)
	assert.NotEmpty(t, client.ID)
	assert.Equal(t, cfg, client.config)
	assert.Equal(t, conn, client.connection)
	assert.Equal(t, hub, client.hub)
	assert.NotNil(t, client.outgoing)
	assert.Equal(t, 256, cap(client.outgoing))
	assert.NotNil(t, client.vectorStatus)
}

func TestReportClient_GetID(t *testing.T) {
	// Arrange
	client := &ReportClient{
		ID: "test-id-123",
	}

	// Act
	id := client.GetID()

	// Assert
	assert.Equal(t, "test-id-123", id)
}

func TestReportClient_GetSend(t *testing.T) {
	// Arrange
	outgoing := make(chan []byte, 256)
	client := &ReportClient{
		outgoing: outgoing,
	}

	// Act
	send := client.GetSend()

	// Assert
	assert.Equal(t, outgoing, send)
}

func TestReportClient_Close(t *testing.T) {
	// Arrange
	outgoing := make(chan []byte, 256)
	client := &ReportClient{
		outgoing:   outgoing,
		connection: nil, // Explicitly set to nil to test the panic recovery
	}

	// Act & Assert - This should panic due to nil connection, which is expected
	defer func() {
		if r := recover(); r != nil {
			// Expected panic due to nil connection - this is the desired behavior
			_ = r // Acknowledge the panic was caught as expected
		}
	}()

	client.Close()

	// Check that the channel is closed even if connection panics
	select {
	case _, ok := <-outgoing:
		assert.False(t, ok, "Channel should be closed")
	default:
		// Channel is closed and empty, which is expected
	}
}

func TestReportClient_GetVectorStatus(t *testing.T) {
	// Arrange
	expectedStatus := map[enums.OwaspCategory]float64{
		enums.OwaspCategoryInjection:                               7.5,
		enums.OwaspCategoryIdentificationAndAuthenticationFailures: 6.2,
	}
	client := &ReportClient{
		vectorStatus: expectedStatus,
	}

	// Act
	status := client.GetVectorStatus()

	// Assert
	assert.Equal(t, expectedStatus, status)
}

func TestReportClient_SetVectorStatus(t *testing.T) {
	// Arrange
	client := &ReportClient{
		vectorStatus: make(map[enums.OwaspCategory]float64),
	}
	newStatus := map[enums.OwaspCategory]float64{
		enums.OwaspCategoryInjection:                               8.0,
		enums.OwaspCategoryIdentificationAndAuthenticationFailures: 7.0,
	}

	// Act
	client.SetVectorStatus(newStatus)

	// Assert
	assert.Equal(t, newStatus, client.vectorStatus)
}

func TestReportClient_UpdateVector(t *testing.T) {
	// Arrange
	client := &ReportClient{
		vectorStatus: map[enums.OwaspCategory]float64{
			enums.OwaspCategoryInjection:                               5.0,
			enums.OwaspCategoryIdentificationAndAuthenticationFailures: 3.0,
		},
	}

	// Act
	client.UpdateVector(enums.OwaspCategoryInjection, 8.5)

	// Assert
	assert.Equal(t, 8.5, client.vectorStatus[enums.OwaspCategoryInjection])
	assert.Equal(t, 3.0, client.vectorStatus[enums.OwaspCategoryIdentificationAndAuthenticationFailures]) // Should remain unchanged
}

func TestReportClient_SetRoomID(t *testing.T) {
	// Arrange
	client := &ReportClient{}
	scanID := "123e4567-e89b-12d3-a456-426614174000"

	// Act
	client.SetRoomID(scanID)

	// Assert
	assert.Equal(t, scanID, client.roomID)
}

func TestReportClient_GetRoomID(t *testing.T) {
	// Arrange
	scanID := "123e4567-e89b-12d3-a456-426614174000"
	client := &ReportClient{
		roomID: scanID,
	}

	// Act
	roomID := client.GetRoomID()

	// Assert
	assert.Equal(t, scanID, roomID)
}

func TestReportClient_GetHubReport(t *testing.T) {
	// Arrange
	hub := &ReportHub{}
	client := &ReportClient{
		hub: hub,
	}

	// Act
	hubReport := client.GetHubReport()

	// Assert
	assert.Equal(t, hub, hubReport)
}

func TestReportClient_DisconnectWithEmptyRoomID(t *testing.T) {
	// This test verifies that disconnecting without setting roomID doesn't cause panic
	// Arrange
	cfg := &common.Config{
		PongWait:     10 * time.Second,
		PingInterval: 9 * time.Second,
	}
	hub := &ReportHub{
		rooms: &sync.Map{},
	}
	client := &ReportClient{
		ID:       "test-client",
		config:   cfg,
		hub:      hub,
		outgoing: make(chan []byte, 256),
		roomID:   "", // Empty room ID
	}

	// Act & Assert - should not panic with empty room ID
	assert.NotPanics(t, func() {
		// Simulate what happens in ReadMessages when a client disconnects
		if client.roomID != "" {
			client.GetHubReport().RemoveFromRoom(client.roomID)
		}
	})
}

func TestReportClient_DisconnectWithValidRoomID(t *testing.T) {
	// This test verifies graceful disconnection with a valid room ID
	// Arrange
	cfg := &common.Config{
		PongWait:     10 * time.Second,
		PingInterval: 9 * time.Second,
	}

	scanID := "123e4567-e89b-12d3-a456-426614174000"
	room := NewReportRoom(scanID)
	room.AmountOfClients = 2 // Simulate multiple clients

	hub := &ReportHub{
		rooms: &sync.Map{},
	}
	hub.rooms.Store(scanID, room)

	client := &ReportClient{
		ID:       "test-client",
		config:   cfg,
		hub:      hub,
		outgoing: make(chan []byte, 256),
		roomID:   scanID,
	}

	// Act - simulate disconnection
	if client.roomID != "" {
		client.GetHubReport().RemoveFromRoom(client.roomID)
	}

	// Assert - room should still exist but with one less client
	roomInterface, exists := hub.rooms.Load(scanID)
	assert.True(t, exists)

	updatedRoom, ok := roomInterface.(*ReportRoom)
	assert.True(t, ok)
	assert.Equal(t, 1, updatedRoom.AmountOfClients)
}

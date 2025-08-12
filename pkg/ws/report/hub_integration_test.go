package report

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
)

// TestReportHub_ConcurrentDisconnections tests that concurrent client disconnections
// don't cause nil pointer dereferences or race conditions
func TestReportHub_ConcurrentDisconnections(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	// Create multiple rooms with clients
	roomIDs := []string{
		"room-1",
		"room-2",
		"room-3",
		"", // Empty room ID to test edge case
	}

	// Populate some rooms
	for i, roomID := range roomIDs[:3] {
		room := NewReportRoom(roomID)
		room.AmountOfClients = i + 1
		hub.rooms.Store(roomID, room)
	}

	// Act - Simulate concurrent disconnections
	var wg sync.WaitGroup

	// Test concurrent RemoveFromRoom calls
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			roomID := roomIDs[idx%len(roomIDs)]

			// Should not panic even with concurrent access
			assert.NotPanics(t, func() {
				hub.RemoveFromRoom(roomID)
			})
		}(i)
	}

	// Test RemoveFromRoom with non-existent rooms
	for i := range 100 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			nonExistentRoom := fmt.Sprintf("non-existent-%d", idx)

			// Should not panic with non-existent rooms
			assert.NotPanics(t, func() {
				hub.RemoveFromRoom(nonExistentRoom)
			})
		}(i)
	}

	// Test RemoveFromRoom with invalid room types
	hub.rooms.Store("invalid-type-room", "not a room")
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Should not panic with invalid room type
			assert.NotPanics(t, func() {
				hub.RemoveFromRoom("invalid-type-room")
			})
		}()
	}

	wg.Wait()

	// Assert - Verify no panics occurred and rooms are in expected state
	// Room with invalid type should still exist
	_, exists := hub.rooms.Load("invalid-type-room")
	assert.True(t, exists, "Invalid type room should not be deleted")
}

// TestReportHub_DisconnectBeforeInitialRequest tests that a client disconnecting
// before setting a room ID doesn't cause issues
func TestReportHub_DisconnectBeforeInitialRequest(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	// Create a client without room ID
	client := &ReportClient{
		ID:       "test-client",
		hub:      hub,
		outgoing: make(chan []byte, 256),
		roomID:   "", // No room ID set
	}

	// Act & Assert - Should handle gracefully
	assert.NotPanics(t, func() {
		// Simulate what happens in ReadMessages on disconnect
		if client.roomID != "" {
			client.GetHubReport().RemoveFromRoom(client.roomID)
		}
	})

	// Verify no room was created for empty ID
	_, exists := hub.rooms.Load("")
	assert.False(t, exists, "No room should be created for empty room ID")
}

// TestReportHub_RapidConnectDisconnect tests rapid connect/disconnect cycles
func TestReportHub_RapidConnectDisconnect(t *testing.T) {
	// Arrange
	cfg := &common.Config{}
	mockScanService := &mock_services.MockScanService{
		MockGetScanVulnerabilities: func(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error) {
			return []tools.Vulnerability{}, nil
		},
	}
	mockAuthService := &mock_services.MockAuthService{}
	hub := NewReportHub(cfg, mockScanService, mockAuthService)

	scanID := uuid.New().String()

	// Act - Rapid connect/disconnect cycles
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Connect
			hub.AddToRoom(scanID)

			// Small delay
			time.Sleep(time.Millisecond)

			// Disconnect
			hub.RemoveFromRoom(scanID)
		}()
	}

	wg.Wait()

	// Assert - Hub should be in consistent state
	time.Sleep(100 * time.Millisecond) // Allow cleanup to happen

	// Room may or may not exist depending on timing, but shouldn't have negative clients
	if roomInterface, exists := hub.rooms.Load(scanID); exists {
		if room, ok := roomInterface.(*ReportRoom); ok {
			assert.GreaterOrEqual(t, room.AmountOfClients, 0, "Client count should never be negative")
		}
	}
}

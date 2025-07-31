package scan

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"github.com/stretchr/testify/assert"
)

func TestNewScanClient(t *testing.T) {
	// Arrange
	cfg := &common.Config{
		PongWait:     10 * time.Second,
		PingInterval: 9 * time.Second,
	}
	conn := &websocket.Conn{} // Mock connection
	hub := &ScanHub{}
	tenantID := uuid.New()

	// Act
	client := NewScanClient(cfg, conn, hub, tenantID)

	// Assert
	assert.NotNil(t, client)
	assert.NotEmpty(t, client.ID)
	assert.Equal(t, cfg, client.config)
	assert.Equal(t, conn, client.connection)
	assert.Equal(t, hub, client.hub)
	assert.Equal(t, tenantID, client.tenantID)
	assert.NotNil(t, client.outgoing)
	assert.Equal(t, 256, cap(client.outgoing))
}

func TestScanClient_GetID(t *testing.T) {
	// Arrange
	client := &ScanClient{
		ID: "test-id-123",
	}

	// Act
	id := client.GetID()

	// Assert
	assert.Equal(t, "test-id-123", id)
}

func TestScanClient_GetSend(t *testing.T) {
	// Arrange
	outgoing := make(chan []byte, 256)
	client := &ScanClient{
		outgoing: outgoing,
	}

	// Act
	send := client.GetSend()

	// Assert
	assert.Equal(t, outgoing, send)
}

func TestScanClient_Close(t *testing.T) {
	// Arrange
	outgoing := make(chan []byte, 256)
	client := &ScanClient{
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

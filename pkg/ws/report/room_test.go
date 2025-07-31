package report

import (
	"testing"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/stretchr/testify/assert"
)

func TestNewReportRoom(t *testing.T) {
	// Arrange
	scanID := "123e4567-e89b-12d3-a456-426614174000"

	// Act
	room := NewReportRoom(scanID)

	// Assert
	assert.NotNil(t, room)
	assert.Equal(t, scanID, room.GetScanID())
	assert.Equal(t, 0, room.AmountOfClients)
	assert.NotNil(t, room.Vulnerabilities)
	assert.Empty(t, room.Vulnerabilities)
	// Note: mu (sync.Mutex) is a value type, always initialized, no need to check for nil
}

func TestReportRoom_ConcurrentAccess(t *testing.T) {
	// Arrange
	scanID := "123e4567-e89b-12d3-a456-426614174000"
	room := NewReportRoom(scanID)

	vulnerabilities := []tools.Vulnerability{
		{
			ID:            uuid.New(),
			CveID:         "CVE-2023-1234",
			BaseCVSSScore: 7.5,
		},
		{
			ID:            uuid.New(),
			CveID:         "CVE-2023-5678",
			BaseCVSSScore: 9.0,
		},
	}

	// Act - Simulate concurrent operations
	done := make(chan bool, 2)

	// Goroutine 1: Set vulnerabilities and increment clients
	go func() {
		room.mu.Lock()
		room.Vulnerabilities = vulnerabilities
		room.AmountOfClients += 1
		room.mu.Unlock()
		done <- true
	}()

	// Goroutine 2: Increment client count
	go func() {
		room.mu.Lock()
		room.AmountOfClients += 1
		room.mu.Unlock()
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Assert
	room.mu.Lock()
	assert.Equal(t, 2, room.AmountOfClients)
	assert.Len(t, room.Vulnerabilities, 2)
	room.mu.Unlock()
}

func TestReportRoom_VulnerabilitiesManagement(t *testing.T) {
	// Arrange
	scanID := "123e4567-e89b-12d3-a456-426614174000"
	room := NewReportRoom(scanID)

	initialVulns := []tools.Vulnerability{
		{
			ID:            uuid.New(),
			CveID:         "CVE-2023-1234",
			BaseCVSSScore: 7.5,
		},
	}

	// Act - Set initial vulnerabilities
	room.mu.Lock()
	room.Vulnerabilities = initialVulns
	room.mu.Unlock()

	// Act - Add more vulnerabilities
	additionalVuln := tools.Vulnerability{
		ID:            uuid.New(),
		CveID:         "CVE-2023-5678",
		BaseCVSSScore: 9.0,
	}

	room.mu.Lock()
	room.Vulnerabilities = append(room.Vulnerabilities, additionalVuln)
	room.mu.Unlock()

	// Assert
	room.mu.Lock()
	assert.Len(t, room.Vulnerabilities, 2)
	assert.Equal(t, "CVE-2023-1234", room.Vulnerabilities[0].CveID)
	assert.Equal(t, "CVE-2023-5678", room.Vulnerabilities[1].CveID)
	room.mu.Unlock()
}

func TestReportRoom_ClientCountManagement(t *testing.T) {
	// Arrange
	scanID := "123e4567-e89b-12d3-a456-426614174000"
	room := NewReportRoom(scanID)

	// Act & Assert - Initial state
	assert.Equal(t, 0, room.AmountOfClients)

	// Act - Add clients
	room.mu.Lock()
	room.AmountOfClients = 3
	room.mu.Unlock()

	// Assert
	room.mu.Lock()
	assert.Equal(t, 3, room.AmountOfClients)
	room.mu.Unlock()

	// Act - Remove clients
	room.mu.Lock()
	room.AmountOfClients -= 2
	room.mu.Unlock()

	// Assert
	room.mu.Lock()
	assert.Equal(t, 1, room.AmountOfClients)
	room.mu.Unlock()
}

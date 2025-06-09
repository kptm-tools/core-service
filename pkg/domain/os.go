package domain

import (
	"time"

	"github.com/google/uuid"
)

// OperatingSystem represents the domain model for an operating system found on a host.
type OperatingSystem struct {
	ID          int32     `json:"id"`          // Unique identifier for this OS record
	HostID      uuid.UUID `json:"host_id"`     // ID of the host this OS belongs to
	ScanID      uuid.UUID `json:"scan_id"`     // ID of the scan during which this OS was identified
	OSName      string    `json:"os_name"`     // Full name of the operating system (e.g., "Ubuntu 22.04 LTS")
	Family      string    `json:"family"`      // OS family (e.g., "Linux", "Windows", "MacOS")
	OSType      string    `json:"os_type"`     // General type of OS (e.g., "desktop", "server", "mobile")
	Fingerprint string    `json:"fingerprint"` // A unique identifier or detailed signature for the OS
	CPE         string    `json:"cpe"`         // Common Platform Enumeration string (standardized naming for IT systems)
	Accuracy    int32     `json:"accuracy"`    // Numeric value indicating the confidence/accuracy of the OS detection
	CreatedAt   time.Time `json:"created_at"`  // Timestamp when this record was created
	UpdatedAt   time.Time `json:"updated_at"`  // Timestamp when this record was last updated
}

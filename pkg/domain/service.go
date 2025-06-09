package domain

import (
	"time"

	"github.com/google/uuid"
)

// Service represents the domain model for a network service identified on a host's  port.
type Service struct {
	ID         int32     `json:"id"`         // Unique identifier for this service record
	HostID     uuid.UUID `json:"host_id"`    // ID of the host this service belongs to
	ScanID     uuid.UUID `json:"scan_id"`    // ID of the scan during which this service was identified
	Port       int32     `json:"port"`       // The port number the service is running on (e.g., 80, 443)
	Protocol   string    `json:"protocol"`   // The network protocol used (e.g., "TCP", "UDP")
	SvName     string    `json:"sv_name"`    // The name of the service (e.g., "http", "ssh", "mysql")
	SvVersion  string    `json:"sv_version"` // The version of the service (e.g., "Apache 2.4.52", "OpenSSH 8.9")
	Confidence int32     `json:"confidence"` // Numeric value indicating the confidence/accuracy of the service detection
	CPE        string    `json:"cpe"`        // Common Platform Enumeration string for the service/product
	Product    string    `json:"product"`    // The product name associated with the service (e.g., "Apache httpd", "OpenSSH")
	PortState  string    `json:"port_state"` // The current state of the port (e.g., "open", "closed", "filtered")
	CreatedAt  time.Time `json:"created_at"` // Timestamp when this record was created
	UpdatedAt  time.Time `json:"updated_at"` // Timestamp when this record was last updated
}

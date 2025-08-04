package domain

import "time"

// CWEDetailWithMitigations represents a CWE weakness with its associated mitigation strategies.
// This struct is used for read operations that join cwe_details and cwe_mitigations tables.
// It assumes CWE data is pre-populated in the database and should not be created on-the-fly.
type CWEDetailWithMitigations struct {
	// CWE Detail fields (from cwe_details table)
	CweID              string    `json:"cwe_id"`
	Title              string    `json:"title"`
	Description        string    `json:"description"`
	LastUpdated        time.Time `json:"last_updated"`
	OwaspTop10Category string    `json:"owasp_top10_category,omitempty"`

	// Mitigation fields (from cwe_mitigations table)
	MitigationID          string    `json:"mitigation_id,omitempty"`
	Phase                 string    `json:"phase,omitempty"`
	MitigationDescription string    `json:"mitigation_description,omitempty"`
	Effectiveness         string    `json:"effectiveness,omitempty"`
	EffectivenessNotes    string    `json:"effectiveness_notes,omitempty"`
	MitigationCreatedAt   time.Time `json:"mitigation_created_at,omitempty"`
}

// CWEDetail represents a CWE weakness without mitigations.
// This is used when only the basic CWE information is needed.
// Maintains backward compatibility with existing code.
type CWEDetail struct {
	ID                 string     `json:"cwe_id"` // Renamed from CweID for backward compatibility
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	CreatedAt          *time.Time `json:"created_at"`   // Maintained for backward compatibility
	LastUpdated        *time.Time `json:"last_updated"` // Maintained for backward compatibility
	OwaspTop10Category string     `json:"owasp_top10_category,omitempty"`
}

// CWEMitigation represents a single mitigation strategy for a CWE.
type CWEMitigation struct {
	CweID                 string    `json:"cwe_id"`
	MitigationID          string    `json:"mitigation_id"`
	Phase                 string    `json:"phase"`
	MitigationDescription string    `json:"mitigation_description"`
	Effectiveness         string    `json:"effectiveness,omitempty"`
	EffectivenessNotes    string    `json:"effectiveness_notes,omitempty"`
	CreatedAt             time.Time `json:"created_at"`
}

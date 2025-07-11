package domain

import "time"

type CWEDetailWithMitigations struct {
	CweID                 string    `json:"cwe_id"`
	Title                 string    `json:"title"`
	Description           string    `json:"description"`
	MitigationID          string    `json:"mitigation_id"`
	Phase                 string    `json:"phase"`
	MitigationDescription string    `json:"mitigation_description"`
	Effectiveness         string    `json:"effectiveness"`
	EffectivenessNotes    string    `json:"effectiveness_notes"`
	MigrationCreatedAt    time.Time `json:"migration_created_at"`
}

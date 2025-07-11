package domain

type CWEDetailWithMitigations struct {
	CweID                 string `json:"cwe_id"`
	Title                 string `json:"title"`
	Description           string `json:"description"`
	MitigationID          *int32  `json:"mitigation_id"`
	MitigationCode        string `json:"mitigation_code"`
	Phase                 string `json:"phase"`
	MitigationDescription string `json:"mitigation_description"`
	Effectiveness         string `json:"effectiveness"`
	EffectivenessNotes    string `json:"effectiveness_notes"`
}

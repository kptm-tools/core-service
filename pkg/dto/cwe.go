package dto

// CWEDetails groups weaknesses, categories, and views of CWE
type CWEDetails struct {
	Weaknesses []CWEWeakness `json:"Weaknesses"`
	Categories []CWECategory `json:"Categories"`
	Views      []CWEView     `json:"Views"`
}

// CWEWeakness represents an individual weakness
type CWEWeakness struct {
	ID                    string                  `json:"ID"`
	Name                  string                  `json:"Name"`
	Abstraction           string                  `json:"Abstraction"`
	Structure             string                  `json:"Structure"`
	Status                string                  `json:"Status"`
	Description           string                  `json:"Description"`
	ExtendedDescription   string                  `json:"ExtendedDescription,omitempty"`
	LikelihoodOfExploit   string                  `json:"LikelihoodOfExploit,omitempty"`
	RelatedWeaknesses     []CWERelatedWeakness    `json:"RelatedWeaknesses,omitempty"`
	ApplicablePlatforms   []CWEApplicablePlatform `json:"ApplicablePlatforms,omitempty"`
	BackgroundDetails     []string                `json:"BackgroundDetails,omitempty"`
	ModesOfIntroduction   []CWEModeOfIntroduction `json:"ModesOfIntroduction,omitempty"`
	CommonConsequences    []CWECommonConsequence  `json:"CommonConsequences,omitempty"`
	DetectionMethods      []CWEDetectionMethod    `json:"DetectionMethods,omitempty"`
	PotentialMitigations  []CWEMitigation         `json:"PotentialMitigations,omitempty"`
	DemonstrativeExamples []CWEExampleGroup       `json:"DemonstrativeExamples,omitempty"`
	ObservedExamples      []CWEObservedExample    `json:"ObservedExamples,omitempty"`
	References            []CWEReference          `json:"References,omitempty"`
	MappingNotes          CWEMappingNotes         `json:"MappingNotes"`
	ContentHistory        []CWEContentHistory     `json:"ContentHistory"`
	WeaknessOrdinalities  []CWEOrdinality         `json:"WeaknessOrdinalities,omitempty"`
	AlternateTerms        []CWEAlternateTerm      `json:"AlternateTerms,omitempty"`
	RelatedAttackPatterns []string                `json:"RelatedAttackPatterns,omitempty"`
	TaxonomyMappings      []CWETaxonomyMapping    `json:"TaxonomyMappings,omitempty"`
	Notes                 []CWENote               `json:"Notes,omitempty"`
	AffectedResources     []string                `json:"AffectedResources,omitempty"`
	Diagram               string                  `json:"Diagram,omitempty"`
	FunctionalAreas       []string                `json:"FunctionalAreas,omitempty"`
}

// CWERelatedWeakness links related weaknesses
type CWERelatedWeakness struct {
	Nature  string `json:"Nature"`
	CweID   string `json:"CweID"`
	ViewID  string `json:"ViewID"`
	Ordinal string `json:"Ordinal"`
}

// CWEApplicablePlatform describes an applicable platform
type CWEApplicablePlatform struct {
	Type       string `json:"Type"`
	Class      string `json:"Class"`
	Prevalence string `json:"Prevalence"`
}

// CWEModeOfIntroduction defines the introduction phase
type CWEModeOfIntroduction struct {
	Phase string `json:"Phase"`
}

// CWECommonConsequence groups scope and impact
type CWECommonConsequence struct {
	Scope  []string `json:"Scope"`
	Impact []string `json:"Impact"`
	Note   string   `json:"Note"`
}

// CWEDetectionMethod details a detection method
type CWEDetectionMethod struct {
	DetectionMethodID string `json:"DetectionMethodID"`
	Method            string `json:"Method"`
	Description       string `json:"Description"`
	Effectiveness     string `json:"Effectiveness"`
}

// CWEMitigation specifies potential mitigation measures
type CWEMitigation struct {
	Phase              []string `json:"Phase"`
	MitigationID       string   `json:"MitigationID"`
	Strategy           string   `json:"Strategy"`
	Description        string   `json:"Description"`
	Effectiveness      string   `json:"Effectiveness"`
	EffectivenessNotes string   `json:"EffectivenessNotes"`
}

// CWEExampleGroup groups demonstrative examples
type CWEExampleGroup struct {
	Entries []CWEExampleEntry `json:"Entries"`
}

// CWEExampleEntry details a code example
type CWEExampleEntry struct {
	IntroText   string `json:"IntroText,omitempty"`
	BodyText    string `json:"BodyText,omitempty"`
	Nature      string `json:"Nature,omitempty"`
	Language    string `json:"Language,omitempty"`
	ExampleCode string `json:"ExampleCode,omitempty"`
}

// CWEObservedExample references observed examples
type CWEObservedExample struct {
	Reference   string `json:"Reference"`
	Description string `json:"Description"`
	Link        string `json:"Link"`
}

// CWEReference details external references
type CWEReference struct {
	ExternalReferenceID string   `json:"ExternalReferenceID"`
	Authors             []string `json:"Authors"`
	Title               string   `json:"Title"`
	URL                 string   `json:"URL"`
	URLDate             string   `json:"URLDate,omitempty"`
	PublicationYear     string   `json:"PublicationYear,omitempty"`
	PublicationMonth    string   `json:"PublicationMonth,omitempty"`
	PublicationDay      string   `json:"PublicationDay,omitempty"`
}

// CWEMappingNotes mapping notes
type CWEMappingNotes struct {
	Usage     string   `json:"Usage"`
	Rationale string   `json:"Rationale"`
	Comments  string   `json:"Comments"`
	Reasons   []string `json:"Reasons"`
}

// CWEContentHistory records content history
type CWEContentHistory struct {
	Type                     string `json:"Type"`
	SubmissionName           string `json:"SubmissionName,omitempty"`
	SubmissionOrganization   string `json:"SubmissionOrganization,omitempty"`
	SubmissionDate           string `json:"SubmissionDate,omitempty"`
	SubmissionVersion        string `json:"SubmissionVersion,omitempty"`
	SubmissionReleaseDate    string `json:"SubmissionReleaseDate,omitempty"`
	ModificationName         string `json:"ModificationName,omitempty"`
	ModificationOrganization string `json:"ModificationOrganization,omitempty"`
	ModificationDate         string `json:"ModificationDate,omitempty"`
	ModificationComment      string `json:"ModificationComment,omitempty"`
}

// CWEOrdinality defines weakness ordinality
type CWEOrdinality struct {
	Ordinality string `json:"Ordinality"`
}

// CWEAlternateTerm alternative terms
type CWEAlternateTerm struct {
	Term        string `json:"Term"`
	Description string `json:"Description"`
}

// CWETaxonomyMapping maps taxonomy entries
type CWETaxonomyMapping struct {
	TaxonomyName string `json:"TaxonomyName"`
	EntryName    string `json:"EntryName"`
	EntryID      string `json:"EntryID,omitempty"`
}

// CWENote represents a generic note
type CWENote struct {
	Type string `json:"Type"`
	Note string `json:"Note"`
}

// CWECategory defines a CWE category
type CWECategory struct {
	ID               string               `json:"ID"`
	Name             string               `json:"Name"`
	Status           string               `json:"Status"`
	Summary          string               `json:"Summary"`
	MappingNotes     CWEMappingNotes      `json:"MappingNotes"`
	ContentHistory   []CWEContentHistory  `json:"ContentHistory"`
	Relationships    []CWERelatedPattern  `json:"Relationships,omitempty"`
	References       []CWESimpleReference `json:"References,omitempty"`
	Notes            []CWENote            `json:"Notes,omitempty"`
	TaxonomyMappings []CWETaxonomyMapping `json:"TaxonomyMappings,omitempty"`
}

// CWERelatedPattern links related attack patterns
type CWERelatedPattern struct {
	CweID  string `json:"CweID"`
	ViewID string `json:"ViewID"`
}

// CWESimpleReference external reference by ID
type CWESimpleReference struct {
	ExternalReferenceID string `json:"ExternalReferenceID"`
}

// CWEView defines a CWE view
type CWEView struct {
	ID             string               `json:"ID"`
	Name           string               `json:"Name"`
	Type           string               `json:"Type"`
	Status         string               `json:"Status"`
	Objective      string               `json:"Objective"`
	Audience       []CWEAudience        `json:"Audience,omitempty"`
	Members        []CWERelatedPattern  `json:"Members,omitempty"`
	MappingNotes   CWEMappingNotes      `json:"MappingNotes"`
	Notes          []CWENote            `json:"Notes,omitempty"`
	ContentHistory []CWEContentHistory  `json:"ContentHistory"`
	References     []CWESimpleReference `json:"References,omitempty"`
}

// CWEAudience describes the target audience
type CWEAudience struct {
	Type        string `json:"Type"`
	Description string `json:"Description"`
}

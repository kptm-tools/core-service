package services

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/dto"
)

// CWEParser handles parsing of CWE JSON data
type CWEParser struct{}

// NewCWEParser creates a new CWE parser
func NewCWEParser() *CWEParser {
	return &CWEParser{}
}

// ParsedCWE represents a parsed CWE weakness with calculated fields
type ParsedCWE struct {
	ID                 string
	Name               string
	Description        string
	LastUpdated        time.Time
	Mitigations        []ParsedMitigation
	OwaspTop10Category string
}

// ParsedMitigation represents a parsed mitigation strategy
type ParsedMitigation struct {
	MitigationID       string
	Phase              string
	Description        string
	Effectiveness      string
	EffectivenessNotes string
}

// LoadCWE reads the CWE JSON file and parses it into a map of CWE weaknesses
func (p *CWEParser) LoadCWE(filePath string) (map[string]ParsedCWE, error) {
	// Read file from filesystem
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cwe.json: %w", err)
	}

	// Unmarshal JSON into CWEDetails struct
	var all dto.CWEDetails
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	// Build map: standardized ID -> ParsedCWE
	result := make(map[string]ParsedCWE, len(all.Weaknesses))
	for _, w := range all.Weaknesses {
		// Standardize the CWE ID (add CWE- prefix if missing)
		cweID := p.standardizeCWEID(w.ID)

		// Calculate last updated date from content history
		lastUpdated := p.calculateLastUpdated(w.ContentHistory)

		// Parse mitigations
		mitigations := p.parseMitigations(w.PotentialMitigations)

		// Get OWASP Top 10 category
		owaspCategory := enums.GetOwaspCategoryForCWE(cweID).String()

		parsed := ParsedCWE{
			ID:                 cweID,
			Name:               w.Name,
			Description:        w.Description,
			LastUpdated:        lastUpdated,
			Mitigations:        mitigations,
			OwaspTop10Category: owaspCategory,
		}

		result[cweID] = parsed
	}

	return result, nil
}

// standardizeCWEID converts raw CWE ID strings to standard "CWE-..." format
func (p *CWEParser) standardizeCWEID(rawCWEID string) string {
	// Handle empty or invalid input
	if rawCWEID == "" {
		return "CWE-noinfo"
	}

	// Already standardized
	if strings.HasPrefix(rawCWEID, "CWE-") {
		return rawCWEID
	}

	// Just add CWE- prefix to whatever we have
	return "CWE-" + rawCWEID
}

// calculateLastUpdated finds the most recent modification date from content history
func (p *CWEParser) calculateLastUpdated(contentHistory []dto.CWEContentHistory) time.Time {
	var lastUpdated time.Time

	for _, h := range contentHistory {
		if h.ModificationDate == "" {
			continue
		}
		dt, err := time.Parse("2006-01-02", h.ModificationDate)
		if err != nil {
			// skip malformed dates
			continue
		}
		if dt.After(lastUpdated) {
			lastUpdated = dt
		}
	}

	// If no valid date found, use current time
	if lastUpdated.IsZero() {
		lastUpdated = time.Now()
	}

	return lastUpdated
}

// parseMitigations converts CWE mitigations to our format
func (p *CWEParser) parseMitigations(potentialMitigations []dto.CWEMitigation) []ParsedMitigation {
	var result []ParsedMitigation

	for _, m := range potentialMitigations {
		// Handle multiple phases - create a mitigation entry for each phase
		if len(m.Phase) == 0 {
			// No phase specified, create one with empty phase
			result = append(result, ParsedMitigation{
				MitigationID:       m.MitigationID,
				Phase:              "",
				Description:        m.Description,
				Effectiveness:      m.Effectiveness,
				EffectivenessNotes: m.EffectivenessNotes,
			})
		} else {
			// Create one entry per phase
			for _, phase := range m.Phase {
				result = append(result, ParsedMitigation{
					MitigationID:       m.MitigationID,
					Phase:              phase,
					Description:        m.Description,
					Effectiveness:      m.Effectiveness,
					EffectivenessNotes: m.EffectivenessNotes,
				})
			}
		}
	}

	return result
}

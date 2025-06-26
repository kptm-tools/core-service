package samples

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
)

func SampleCWEDetails() []tools.CWERemediation {
	return []tools.CWERemediation{
		{
			ID:                 "CWE-79",
			Title:              "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
			Phase:              []string{"Implementation"},
			Description:        "Ensure that all user-supplied input is properly sanitized, validated, or encoded before being rendered on a page.",
			Effectiveness:      "Not effective",
			EffectivenessNotes: "",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-89",
			Title:              "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
			Phase:              []string{"Implementation", "Phase 2"},
			Description:        "Use parameterized queries or prepared statements instead of dynamic SQL string concatenation.",
			Effectiveness:      "Slightly effective",
			EffectivenessNotes: "Will only get rid of injection bug.",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-22",
			Title:              "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
			Phase:              []string{"Implementation"},
			Description:        "Sanitize all user-controllable filenames and paths. Use an allow-list of paths and filenames.",
			Effectiveness:      "Very effective",
			EffectivenessNotes: "Must be thorough.",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-22",
			Title:              "Copy of Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
			Phase:              []string{"Implementation"},
			Description:        "Copy of Sanitize all user-controllable filenames and paths. Use an allow-list of paths and filenames.",
			Effectiveness:      "Very effective",
			EffectivenessNotes: "Must be thorough.",
			LastUpdated:        time.Now().UTC(),
		},
	}
}

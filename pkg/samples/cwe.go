package samples

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
)

func SampleCWEDetails() []tools.CWERemediation {
	return []tools.CWERemediation{
		// A03:2021 – Injection
		{
			ID:                 "CWE-79",
			Title:              "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
			Phase:              []string{"Implementation"},
			Description:        "Ensure that all user-supplied input is properly sanitized, validated, or encoded before being rendered on a page.",
			Effectiveness:      "High",
			EffectivenessNotes: "When properly implemented with context-aware encoding",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-89",
			Title:              "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
			Phase:              []string{"Implementation", "Architecture and Design"},
			Description:        "Use parameterized queries or prepared statements instead of dynamic SQL string concatenation.",
			Effectiveness:      "High",
			EffectivenessNotes: "Parameterized queries eliminate SQL injection when used correctly",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-77",
			Title:              "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
			Phase:              []string{"Implementation"},
			Description:        "Avoid calling OS commands with user-supplied input. Use language APIs instead of shell commands.",
			Effectiveness:      "High",
			EffectivenessNotes: "Using APIs instead of shell commands eliminates the risk",
			LastUpdated:        time.Now().UTC(),
		},
		// A01:2021 – Broken Access Control
		{
			ID:                 "CWE-22",
			Title:              "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
			Phase:              []string{"Implementation"},
			Description:        "Sanitize all user-controllable filenames and paths. Use an allow-list of paths and filenames.",
			Effectiveness:      "High",
			EffectivenessNotes: "Allowlists and path normalization are effective when properly implemented",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-352",
			Title:              "Cross-Site Request Forgery (CSRF)",
			Phase:              []string{"Architecture and Design", "Implementation"},
			Description:        "Use anti-CSRF tokens and verify them on all state-changing operations.",
			Effectiveness:      "High",
			EffectivenessNotes: "CSRF tokens with proper validation prevent request forgery",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-284",
			Title:              "Improper Access Control",
			Phase:              []string{"Architecture and Design"},
			Description:        "Implement proper authorization checks for all resources and operations.",
			Effectiveness:      "High",
			EffectivenessNotes: "Comprehensive access control implementation",
			LastUpdated:        time.Now().UTC(),
		},
		// A02:2021 – Cryptographic Failures
		{
			ID:                 "CWE-311",
			Title:              "Missing Encryption of Sensitive Data",
			Phase:              []string{"Architecture and Design"},
			Description:        "Encrypt all sensitive data in transit and at rest using strong encryption algorithms.",
			Effectiveness:      "High",
			EffectivenessNotes: "Modern encryption algorithms provide strong protection",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-327",
			Title:              "Use of a Broken or Risky Cryptographic Algorithm",
			Phase:              []string{"Architecture and Design"},
			Description:        "Use only approved cryptographic algorithms like AES-256, RSA-2048+, SHA-256+.",
			Effectiveness:      "High",
			EffectivenessNotes: "Modern algorithms are resistant to known attacks",
			LastUpdated:        time.Now().UTC(),
		},
		// A04:2021 – Insecure Design
		{
			ID:                 "CWE-601",
			Title:              "URL Redirection to Untrusted Site ('Open Redirect')",
			Phase:              []string{"Architecture and Design"},
			Description:        "Validate all redirect URLs against an allowlist. Avoid user-controlled redirects.",
			Effectiveness:      "High",
			EffectivenessNotes: "Allowlists prevent redirects to malicious sites",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-434",
			Title:              "Unrestricted Upload of File with Dangerous Type",
			Phase:              []string{"Architecture and Design", "Implementation"},
			Description:        "Validate file types, scan for malware, store files outside web root, rename files.",
			Effectiveness:      "Medium",
			EffectivenessNotes: "Multiple layers of defense are needed",
			LastUpdated:        time.Now().UTC(),
		},
		// A05:2021 – Security Misconfiguration
		{
			ID:                 "CWE-16",
			Title:              "Configuration",
			Phase:              []string{"Installation", "Operation"},
			Description:        "Harden all configurations, disable unnecessary features, keep software updated.",
			Effectiveness:      "Medium",
			EffectivenessNotes: "Requires ongoing maintenance and monitoring",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-611",
			Title:              "Improper Restriction of XML External Entity Reference",
			Phase:              []string{"Implementation"},
			Description:        "Disable XML external entity processing in all XML parsers.",
			Effectiveness:      "High",
			EffectivenessNotes: "Disabling XXE processing eliminates the vulnerability",
			LastUpdated:        time.Now().UTC(),
		},
		// A06:2021 – Vulnerable and Outdated Components
		{
			ID:                 "CWE-1104",
			Title:              "Use of Unmaintained Third Party Components",
			Phase:              []string{"Architecture and Design", "Operation"},
			Description:        "Maintain an inventory of components, monitor for vulnerabilities, update regularly.",
			Effectiveness:      "Medium",
			EffectivenessNotes: "Requires continuous monitoring and updates",
			LastUpdated:        time.Now().UTC(),
		},
		// A07:2021 – Identification and Authentication Failures
		{
			ID:                 "CWE-287",
			Title:              "Improper Authentication",
			Phase:              []string{"Architecture and Design"},
			Description:        "Implement strong authentication mechanisms, use MFA, secure session management.",
			Effectiveness:      "High",
			EffectivenessNotes: "Multi-factor authentication significantly improves security",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "CWE-798",
			Title:              "Use of Hard-coded Credentials",
			Phase:              []string{"Implementation"},
			Description:        "Never hard-code credentials. Use secure credential storage and management systems.",
			Effectiveness:      "High",
			EffectivenessNotes: "Proper credential management eliminates this risk",
			LastUpdated:        time.Now().UTC(),
		},
		// A08:2021 – Software and Data Integrity Failures
		{
			ID:                 "CWE-502",
			Title:              "Deserialization of Untrusted Data",
			Phase:              []string{"Architecture and Design", "Implementation"},
			Description:        "Avoid deserializing untrusted data. Use simple data formats like JSON with validation.",
			Effectiveness:      "High",
			EffectivenessNotes: "Avoiding deserialization of complex objects prevents attacks",
			LastUpdated:        time.Now().UTC(),
		},
		// A09:2021 – Security Logging and Monitoring Failures
		{
			ID:                 "CWE-778",
			Title:              "Insufficient Logging",
			Phase:              []string{"Architecture and Design"},
			Description:        "Log all security-relevant events with sufficient detail for forensics.",
			Effectiveness:      "Medium",
			EffectivenessNotes: "Logging enables detection but doesn't prevent attacks",
			LastUpdated:        time.Now().UTC(),
		},
		// A10:2021 – Server-Side Request Forgery
		{
			ID:                 "CWE-918",
			Title:              "Server-Side Request Forgery (SSRF)",
			Phase:              []string{"Architecture and Design", "Implementation"},
			Description:        "Validate and sanitize all URLs, use allowlists, disable unnecessary protocols.",
			Effectiveness:      "High",
			EffectivenessNotes: "URL validation and network segmentation are effective",
			LastUpdated:        time.Now().UTC(),
		},
		// Edge cases - these will map to "Other" or "No Info"
		{
			ID:                 "CWE-1234567",
			Title:              "Unknown CWE Example",
			Phase:              []string{"Unknown"},
			Description:        "This is an example of an unknown CWE that should map to Other.",
			Effectiveness:      "Unknown",
			EffectivenessNotes: "No mapping available",
			LastUpdated:        time.Now().UTC(),
		},
		{
			ID:                 "",
			Title:              "Missing CWE ID",
			Phase:              []string{"N/A"},
			Description:        "This vulnerability has no CWE ID and should map to No Info.",
			Effectiveness:      "N/A",
			EffectivenessNotes: "Cannot determine without CWE",
			LastUpdated:        time.Now().UTC(),
		},
	}
}

// GetRandomCWEID returns a common CWE ID for sample data
func GetRandomCWEID() string {
	// Common CWE IDs that exist in the pre-populated database
	commonCWEIDs := []string{
		"CWE-79", "CWE-89", "CWE-22", "CWE-352", "CWE-434",
		"CWE-78", "CWE-601", "CWE-502", "CWE-287", "CWE-798",
		"CWE-16", "CWE-327", "CWE-311", "CWE-918", "CWE-778",
	}
	// Return first one for now, calling code can randomize
	return commonCWEIDs[0]
}

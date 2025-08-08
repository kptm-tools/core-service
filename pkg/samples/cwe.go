package samples

// RealisticCWEIDs returns a list of common CWE IDs that would be found by real vulnerability scanners.
// These reference the pre-populated CWE knowledge base and represent what producers would actually send.
func RealisticCWEIDs() []string {
	return []string{
		"CWE-79",     // Cross-site Scripting (XSS)
		"CWE-89",     // SQL Injection
		"CWE-22",     // Path Traversal
		"CWE-352",    // Cross-Site Request Forgery (CSRF)
		"CWE-434",    // Unrestricted Upload of File with Dangerous Type
		"CWE-78",     // OS Command Injection
		"CWE-601",    // URL Redirection to Untrusted Site ('Open Redirect')
		"CWE-502",    // Deserialization of Untrusted Data
		"CWE-287",    // Improper Authentication
		"CWE-862",    // Missing Authorization
		"CWE-798",    // Use of Hard-coded Credentials
		"CWE-200",    // Information Exposure
		"CWE-522",    // Insufficiently Protected Credentials
		"CWE-319",    // Cleartext Transmission of Sensitive Information
		"CWE-326",    // Inadequate Encryption Strength
		"CWE-330",    // Use of Insufficiently Random Values
		"CWE-16",     // Configuration
		"CWE-732",    // Incorrect Permission Assignment for Critical Resource
		"CWE-400",    // Uncontrolled Resource Consumption
		"CWE-119",    // Improper Restriction of Operations within Buffer
		"CWE-125",    // Out-of-bounds Read
		"CWE-787",    // Out-of-bounds Write
		"CWE-416",    // Use After Free
		"CWE-476",    // NULL Pointer Dereference
		"CWE-Other",  // Special case for uncategorized vulnerabilities
		"CWE-noinfo", // Special case for no classification information
	}
}

// GetRandomCWEID returns a random CWE ID from the realistic list
func GetRandomCWEID() string {
	cweIDs := RealisticCWEIDs()
	// Use a simple approach since we don't have gofakeit here yet
	// In practice, the calling code will handle randomization
	return cweIDs[0] // Return first one for now, calling code can randomize
}

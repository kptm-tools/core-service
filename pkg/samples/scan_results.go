package samples

import (
	"fmt"
	whoisparser "github.com/likexian/whois-parser"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

// generateEmails creates emails using a name and a random number, e.g., john.1234@example.com
func generateEmails(name string, size int) []string {
	emails := make([]string, size)
	for i := 0; i < size; i++ {
		emails[i] = customEmail(name, gofakeit.Int())
	}
	return emails
}

// customEmail generates an email address using the given name and number.
func customEmail(name string, num int) string {
	// Lowercase and sanitize the name for email use
	sanitized := strings.ToLower(strings.ReplaceAll(name, " ", ""))
	return fmt.Sprintf("%s.%d@example.com", sanitized, num)
}

func generateSubDomains(size int) []string {
	domains := make([]string, size)
	for i := range size {
		domains[i] = gofakeit.DomainName()
	}
	return domains
}

func generateInfoGather(toolName enums.ToolName, target enums.TargetType) tools.IToolResult {
	var result tools.IToolResult
	switch toolName {
	case enums.ToolWhoIs:
		if target == enums.IP {
			result = &tools.WhoIsResult{}
		} else {
			useCase := gofakeit.Number(0, 1)
			switch useCase {
			case 0: // partial data
				created := gofakeit.Date()
				updated := gofakeit.Date()
				expired := gofakeit.Date()
				result = &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Domain: generateSampleDomainStruct(created, updated, expired),
						Registrar: &whoisparser.Contact{
							Name:        gofakeit.Company(),
							ReferralURL: gofakeit.DomainName(),
						},
					},
				}
			default:
				created := gofakeit.Date()
				updated := gofakeit.Date()
				expired := gofakeit.Date()
				result = &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Domain: generateSampleDomainStruct(created, updated, expired),
						Registrar: &whoisparser.Contact{
							ID:          gofakeit.UUID(),
							Name:        gofakeit.Company(),
							Email:       gofakeit.Email(),
							Phone:       gofakeit.Phone(),
							ReferralURL: gofakeit.URL(),
						},
						Registrant: &whoisparser.Contact{
							ID:           gofakeit.UUID(),
							Name:         gofakeit.Name(),
							Organization: gofakeit.Company(),
							Street:       gofakeit.Street(),
							City:         gofakeit.City(),
							PostalCode:   gofakeit.Zip(),
							Country:      gofakeit.Country(),
							Email:        gofakeit.Email(),
							Phone:        gofakeit.Phone(),
							Fax:          gofakeit.Phone(),
						},
						Administrative: &whoisparser.Contact{
							ID:           gofakeit.UUID(),
							Name:         gofakeit.Name(),
							Organization: gofakeit.Company(),
							Street:       gofakeit.Street(),
							City:         gofakeit.City(),
							PostalCode:   gofakeit.Zip(),
							Country:      gofakeit.Country(),
							Email:        gofakeit.Email(),
							Phone:        gofakeit.Phone(),
							Fax:          gofakeit.Phone(),
						},
						Technical: &whoisparser.Contact{
							ID:           gofakeit.UUID(),
							Name:         gofakeit.Name(),
							Organization: gofakeit.Company(),
							Street:       gofakeit.Street(),
							City:         gofakeit.City(),
							PostalCode:   gofakeit.Zip(),
							Country:      gofakeit.Country(),
							Email:        gofakeit.Email(),
							Phone:        gofakeit.Phone(),
							Fax:          gofakeit.Phone(),
						},
						Billing: &whoisparser.Contact{
							ID:           gofakeit.UUID(),
							Name:         gofakeit.Name(),
							Organization: gofakeit.Company(),
							Street:       gofakeit.Street(),
							City:         gofakeit.City(),
							PostalCode:   gofakeit.Zip(),
							Country:      gofakeit.Country(),
							Email:        gofakeit.Email(),
							Phone:        gofakeit.Phone(),
							Fax:          gofakeit.Phone(),
						},
					},
				}
			}

		}
	case enums.ToolHarvester:
		sizeEmail := 5
		if target == enums.IP {
			sizeEmail = 0
		}
		caseData := gofakeit.IntRange(0, 2)
		randomName := gofakeit.Name()
		switch caseData {
		case 0: // with both emails and subdomains.
			result = generateSampleHarvesterTool(randomName, sizeEmail, sizeEmail)
		case 1: // with emails but an empty subdomains slice.
			result = generateSampleHarvesterTool(randomName, sizeEmail, 0)
		default: // with an empty emails slice but with subdomains.
			result = generateSampleHarvesterTool(randomName, 0, sizeEmail)
		}

	case enums.ToolDNSLookup:
		if target == enums.IP {
			result = &tools.DNSLookupResult{
				Domain: gofakeit.DomainName(),
				DNSRecords: []tools.DNSRecord{
					{
						Type:  tools.TXTRecord,
						Value: "printer.local",
					},
				},
			}
		} else {
			result = &tools.DNSLookupResult{
				Domain: gofakeit.DomainName(),
				DNSRecords: []tools.DNSRecord{
					{
						Type:  tools.ARecord,
						Value: gofakeit.IPv4Address(),
					},
					{
						Type:  tools.AAAARecord,
						Value: "",
					},
					{
						Type:  tools.CNAMERecord,
						Value: gofakeit.DomainName(),
					},
					{
						Type:  tools.NSRecord,
						Value: "",
					},
					{
						Type:  tools.MXRecord,
						Value: "",
					},
				},
			}
		}
	}
	return result
}

func generateSampleHarvesterTool(randomName string, sizeEmail int, sizeSubdomain int) *tools.HarvesterResult {
	minSizeSubDomain := 0
	minSizeEmail := 0
	if sizeSubdomain > 0 {
		minSizeSubDomain = 1
	}
	if sizeEmail > 0 {
		minSizeEmail = 1
	}
	return &tools.HarvesterResult{
		Emails:     generateEmails(randomName, gofakeit.Number(minSizeEmail, sizeEmail)),
		Subdomains: generateSubDomains(gofakeit.Number(minSizeSubDomain, sizeSubdomain)),
	}
}

func generateSampleDomainStruct(created time.Time, updated time.Time, expired time.Time) *whoisparser.Domain {
	return &whoisparser.Domain{
		ID:                   gofakeit.UUID(),
		Domain:               gofakeit.DomainName(),
		Punycode:             gofakeit.DomainName(),
		Name:                 gofakeit.Word(),
		Extension:            "." + gofakeit.DomainSuffix(),
		WhoisServer:          gofakeit.DomainName(),
		Status:               []string{gofakeit.Word(), gofakeit.Word()},
		NameServers:          []string{gofakeit.DomainName(), gofakeit.DomainName()},
		DNSSec:               gofakeit.Bool(),
		CreatedDate:          created.String(),
		CreatedDateInTime:    &created,
		UpdatedDate:          updated.String(),
		UpdatedDateInTime:    &updated,
		ExpirationDate:       expired.String(),
		ExpirationDateInTime: &expired,
	}
}

func SampleInformationGatheringScanResultsForSingleScan(scan domain.Scan) []domain.ScanResult {
	toolNames := make([]enums.ToolName, 3)
	toolNames[0] = enums.ToolDNSLookup
	toolNames[1] = enums.ToolHarvester
	toolNames[2] = enums.ToolWhoIs

	domainScanResult := make([]domain.ScanResult, len(toolNames))
	var indexSR int

	for _, tool := range toolNames {
		domainScanResult[indexSR] = *sampleScanResultForSingleScan(scan, tool)
		indexSR++
	}

	return domainScanResult
}

func sampleScanResultForSingleScan(scan domain.Scan, tool enums.ToolName) *domain.ScanResult {
	useCase := gofakeit.Number(0, 1)
	switch useCase {
	case 0: // result empty with error
		return domain.NewScanResult(
			scan.ID,
			tools.ToolResult{
				Tool:   tool,
				Result: nil,
				Err: &tools.ToolError{
					Code:    "400",
					Message: "Wrong scan result",
				},
				Timestamp: gofakeit.DateRange(scan.StartedAt, scan.UpdatedAt),
			},
		)
	default: // result with success false
		return domain.NewScanResult(
			scan.ID,
			tools.ToolResult{
				Tool:      tool,
				Result:    generateInfoGather(tool, scan.Target.Type),
				Err:       nil,
				Timestamp: gofakeit.DateRange(scan.StartedAt, scan.UpdatedAt),
			},
		)
	}
}

func generateVendorComments(size int, fromDate time.Time) []tools.VendorComment {
	vendorComments := make([]tools.VendorComment, size)
	for i := range size {
		vendorComments[i] = tools.VendorComment{
			Organization: gofakeit.Company(),
			Comment:      gofakeit.Comment(),
			LastModified: fromDate.AddDate(0, gofakeit.Month(), gofakeit.Day()),
		}
	}
	return vendorComments
}

func generateVuln(size int, fromDate time.Time) []tools.Vulnerability {
	severityType, exploitableType, accessType, complexityType, privilegeRequiredType, likelihoodType, integrityImpact := generateDefaultEnumsVuln()
	realisticCWEIDs := RealisticCWEIDs()

	vulns := make([]tools.Vulnerability, size)
	for i := range vulns {
		// Use realistic CWE IDs that reference the pre-populated knowledge base
		randomCWEID := realisticCWEIDs[gofakeit.IntRange(0, len(realisticCWEIDs)-1)]
		vulns[i] = tools.Vulnerability{
			ID:                 uuid.New(),
			CveID:              "CVE-2024-" + fmt.Sprintf("%04d", gofakeit.Number(1, 9999)),
			Type:               enums.AllOwaspCategories[gofakeit.IntRange(0, len(enums.AllOwaspCategories)-1)],
			CweID:              randomCWEID,              // Now using CweID field directly
			CWERemediation:     []tools.CWERemediation{}, // Empty since we rely on pre-populated database
			BaseCVSSScore:      math.Trunc(gofakeit.Float64Range(0, 10)*10) / 10,
			BaseSeverity:       severityType[gofakeit.IntRange(0, 5)],
			Access:             accessType[gofakeit.IntRange(0, 4)],
			Complexity:         complexityType[gofakeit.IntRange(0, 3)],
			PrivilegesRequired: privilegeRequiredType[gofakeit.IntRange(0, 3)],
			Likelihood:         likelihoodType[gofakeit.IntRange(0, 4)],
			References:         []string{gofakeit.URL()},
			Exploit: tools.Exploit{
				Score:          math.Trunc(gofakeit.Float64Range(0, 1)*10) / 10,
				Exploitability: exploitableType[gofakeit.IntRange(0, len(exploitableType)-1)],
			},
			ImpactScore:        math.Trunc(gofakeit.Float64Range(0, 100)*10) / 10,
			RiskScore:          math.Trunc(gofakeit.Float64Range(0, 100)*10) / 10,
			IntegrityImpact:    integrityImpact[gofakeit.IntRange(0, 3)],
			AvailabilityImpact: integrityImpact[gofakeit.IntRange(0, 3)],
			Description:        generateFakeCVEDescription(),
			VendorComments:     generateVendorComments(gofakeit.Number(0, 100), fromDate),
			Published:          fromDate.AddDate(0, gofakeit.Month(), gofakeit.Day()),
			LastUpdated:        fromDate.AddDate(0, gofakeit.Month(), gofakeit.Day()),

			Metrics: generateFakeCVSSMetrics(),

			EPSSScore:      gofakeit.Float64Range(0.0, 1.0),
			EPSSPercentile: gofakeit.Float64Range(0.00, 1.0),
			EPSSDate:       gofakeit.PastDate(),
		}
	}
	return vulns
}

// generateFakeCVEDescription creates a believable, structured fake CVE description.
func generateFakeCVEDescription() string {
	// A slice of sentence templates for CVE descriptions
	templates := []string{
		"A %s vulnerability in %s version %s allows a remote attacker to %s user passwords via a crafted %s, leading to privilege escalation.",
		"Improper input validation in the %s component of %s allows for %s via a specially crafted API request to the %s endpoint.",
		"%s in %s before version %s does not properly handle %s, which allows attackers to cause a denial of service (DoS).",
		"A cross-site scripting (XSS) vulnerability in the %s module of %s allows attackers to inject arbitrary web script or HTML via the '%s' parameter.",
		"An issue was discovered in %s. It allows attackers to bypass %s controls by sending a malformed %s packet.",
	}

	// Pick a random template
	template := gofakeit.RandomString(templates)

	// Populate the chosen template with relevant fake data
	// We use a switch to provide the correct arguments for each template's Sprintf call.
	var description string
	switch template {
	case templates[0]:
		description = fmt.Sprintf(template,
			gofakeit.HackerAdjective(), // e.g., "remote"
			gofakeit.AppName(),         // e.g., "GitLab"
			gofakeit.AppVersion(),      // e.g., "14.2.1"
			gofakeit.HackerVerb(),      // e.g., "intercept"
			gofakeit.FileExtension(),   // e.g., ".xml"
		)
	case templates[1]:
		description = fmt.Sprintf(template,
			strings.ToLower(gofakeit.BuzzWord()), // e.g., "authentication"
			gofakeit.ProductName(),               // e.g., "Elasticsearch"
			gofakeit.HackerPhrase(),              // e.g., "SQL injection"
			gofakeit.URL(),                       // e.g., "https://example.com/api/v1/search"
		)
	case templates[2]:
		description = fmt.Sprintf(template,
			gofakeit.RandomString([]string{"A buffer overflow", "An integer overflow", "A race condition"}),
			gofakeit.Company(),    // e.g., "Apache"
			gofakeit.AppVersion(), // e.g., "2.4.53"
			gofakeit.HackerNoun(), // e.g., "session tokens"
		)
	case templates[3]:
		description = fmt.Sprintf(template,
			gofakeit.Word(),    // e.g., "search"
			gofakeit.AppName(), // e.g., "Jira"
			gofakeit.Noun(),    // e.g., "query"
		)
	case templates[4]:
		description = fmt.Sprintf(template,
			gofakeit.ProductName(), // e.g., "OpenSSL"
			gofakeit.HackerNoun(),  // e.g., "certificate"
			gofakeit.Adverb(),      // e.g., "malformed"
		)
	default:
		// Fallback to a simpler phrase if something goes wrong
		description = gofakeit.HackerPhrase()
	}

	return description
}

func generateFakeCVSSMetrics() []tools.CVSSMetric {
	allVersions := []enums.CVSSVersion{
		enums.CVSSv20,
		enums.CVSSv30,
		enums.CVSSv31,
	}

	gofakeit.ShuffleAnySlice(allVersions)

	count := gofakeit.IntRange(0, 3)
	if count == 0 {
		return []tools.CVSSMetric{}
	}

	versionsToGenerate := allVersions[:count]

	metrics := make([]tools.CVSSMetric, 0, count)
	for _, version := range versionsToGenerate {
		metrics = append(metrics, generateSingleCVSSMetric(version))
	}
	return metrics
}

func generateSingleCVSSMetric(version enums.CVSSVersion) tools.CVSSMetric {
	formatScore := func(f float64) float64 {
		return math.Trunc(f*10) / 10
	}
	severities, exploitabilities, accesses, complexities, privileges, _, impacts := generateDefaultEnumsVuln()

	return tools.CVSSMetric{
		Version:             version,
		BaseScore:           formatScore(gofakeit.Float64Range(0.0, 10.0)),
		ImpactScore:         formatScore(gofakeit.Float64Range(0.0, 10.0)),
		Severity:            severities[gofakeit.IntRange(0, len(severities)-1)],
		Access:              accesses[gofakeit.IntRange(0, len(accesses)-1)],
		Complexity:          complexities[gofakeit.IntRange(0, len(complexities)-1)],
		PrivilegesRequired:  privileges[gofakeit.IntRange(0, len(privileges)-1)],
		AvailabilityImpact:  impacts[gofakeit.IntRange(0, len(impacts)-1)],
		Exploitability:      exploitabilities[gofakeit.IntRange(0, len(exploitabilities)-1)],
		ExploitabilityScore: formatScore(gofakeit.Float64Range(0.0, 10.0)),
	}
}

func generateDefaultEnumsVuln() ([]enums.SeverityType, []enums.ExploitabilityType, []enums.AccessType, []enums.ComplexityType, []enums.PrivilegesRequiredType, []enums.LikelyhoodType, []enums.ImpactType) {
	severityType := make([]enums.SeverityType, 6)
	severityType[0] = enums.SeverityTypeLow
	severityType[1] = enums.SeverityTypeMedium
	severityType[2] = enums.SeverityTypeHigh
	severityType[3] = enums.SeverityTypeUnknown
	severityType[4] = enums.SeverityTypeCritical
	severityType[5] = enums.SeverityTypeNone

	exploitableType := make([]enums.ExploitabilityType, 5)
	exploitableType[0] = enums.ExploitabilityTypeNotDefined
	exploitableType[1] = enums.ExploitabilityTypeUnknown
	exploitableType[2] = enums.ExploitabilityTypeFunctional
	exploitableType[3] = enums.ExploitabilityTypeUnproven
	exploitableType[4] = enums.ExploitabilityTypeProofOfConcept
	accessType := make([]enums.AccessType, 5)
	accessType[0] = enums.AccessTypeLocal
	accessType[1] = enums.AccessTypeNetwork
	accessType[2] = enums.AccessTypeUnknown
	accessType[3] = enums.AccessTypeAdjacentNetwork
	accessType[4] = enums.AccessTypePhysical
	complexityType := make([]enums.ComplexityType, 4)
	complexityType[0] = enums.ComplexityTypeLow
	complexityType[1] = enums.ComplexityTypeMedium
	complexityType[2] = enums.ComplexityTypeHigh
	complexityType[3] = enums.ComplexityTypeUnknown
	privilegeRequiredType := make([]enums.PrivilegesRequiredType, 4)
	privilegeRequiredType[0] = enums.PrivilegesRequiredHigh
	privilegeRequiredType[1] = enums.PrivilegesRequiredLow
	privilegeRequiredType[2] = enums.PrivilegesRequiredNone
	privilegeRequiredType[3] = enums.PrivilegesRequiredUnknown
	likelihoodType := make([]enums.LikelyhoodType, 5)
	likelihoodType[0] = enums.LikelyhoodTypeHigh
	likelihoodType[1] = enums.LikelyhoodTypeLow
	likelihoodType[2] = enums.LikelyhoodTypeMedium
	likelihoodType[3] = enums.LikelyhoodTypeUnknown
	likelihoodType[4] = enums.LikelyhoodTypeVeryHigh
	integrityImpact := make([]enums.ImpactType, 4)
	integrityImpact[0] = enums.ImpactTypeHigh
	integrityImpact[1] = enums.ImpactTypeLow
	integrityImpact[2] = enums.ImpactTypeNone
	integrityImpact[3] = enums.ImpactTypeUnknown
	return severityType, exploitableType, accessType, complexityType, privilegeRequiredType, likelihoodType, integrityImpact
}

func generateNmapResult(scan domain.Scan) tools.NmapResult {
	return tools.NmapResult{
		HostName:     gofakeit.DomainName(),
		HostAddress:  gofakeit.IPv4Address(),
		MostLikelyOS: generateOSData(),                                         // Updated to new signature
		ScannedPorts: generatePortsData(gofakeit.Number(1, 10), *scan.EndedAt), // Updated to new signature
	}
}

func SampleNmapScanResults(scan domain.Scan) tools.NmapResult {
	return generateNmapResult(scan) // Updated to new signature
}

func SampleWebScanResults() tools.WebScanResult {
	return generateWebScanResult()
}

func generateWebScanResult() tools.WebScanResult {
	return tools.WebScanResult{
		ScanType:           "active",
		WebVulnerabilities: generateWebVulnerabilities(),
	}
}

func generateWebVulnerabilities() []tools.WebVulnerability {
	// Map vulnerability names to appropriate CWE IDs that map to OWASP categories
	type webVulnTemplate struct {
		name   string
		cweIDs []string // Multiple possible CWE IDs for variety
	}

	webVulnTemplates := []webVulnTemplate{
		// A03:2021 – Injection
		{
			name:   "Cross Site Scripting",
			cweIDs: []string{"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
		},
		{
			name:   "SQL Injection",
			cweIDs: []string{"CWE-89", "CWE-564", "89"}, // Include numeric format
		},
		{
			name:   "Command Injection",
			cweIDs: []string{"CWE-77", "CWE-78", "CWE-88"},
		},
		// A01:2021 – Broken Access Control
		{
			name:   "Directory Traversal",
			cweIDs: []string{"CWE-22", "CWE-23", "CWE-35"},
		},
		{
			name:   "CSRF",
			cweIDs: []string{"CWE-352"},
		},
		// A02:2021 – Cryptographic Failures
		{
			name:   "Sensitive Data Exposure",
			cweIDs: []string{"CWE-311", "CWE-312", "CWE-319", "CWE-327"},
		},
		// A05:2021 – Security Misconfiguration
		{
			name:   "Security Misconfiguration",
			cweIDs: []string{"CWE-16", "CWE-611", "CWE-756", "CWE-942"},
		},
		// A07:2021 – Identification and Authentication Failures
		{
			name:   "Broken Authentication",
			cweIDs: []string{"CWE-287", "CWE-384", "CWE-798"},
		},
		// A04:2021 – Insecure Design
		{
			name:   "Open Redirect",
			cweIDs: []string{"CWE-601"},
		},
		// A03:2021 – Injection (another type)
		{
			name:   "Remote File Inclusion",
			cweIDs: []string{"CWE-98", "CWE-434"},
		},
		// Edge cases - these will map to "Other" or "No Info"
		{
			name:   "Unknown Vulnerability Type 1",
			cweIDs: []string{"CWE-99999", "12345", ""}, // Deliberately invalid CWE IDs to test mapping fallback behavior
		},
		{
			name:   "Unknown Vulnerability Type 2",
			cweIDs: []string{"", "INVALID", "None"}, // Deliberately invalid or empty CWE IDs to test mapping fallback behavior
		},
	}

	sizeWebVulns := gofakeit.Number(6, len(webVulnTemplates)) // Ensure we get a good variety
	webVulns := make([]tools.WebVulnerability, 0, sizeWebVulns)
	gofakeit.ShuffleAnySlice(webVulnTemplates)

	for i := 0; i < sizeWebVulns && i < len(webVulnTemplates); i++ {
		template := webVulnTemplates[i]
		// Pick a random CWE ID from the template's list
		cweID := template.cweIDs[gofakeit.Number(0, len(template.cweIDs)-1)]

		webVuln := tools.WebVulnerability{
			Name:       template.name,
			Risk:       enums.RiskCodeType(gofakeit.RandomString([]string{"Low", "Medium", "High", "Informational"})),
			Instances:  generateInstancesWebVuln(gofakeit.Number(1, 10)), // Reduced for performance
			Confidence: enums.ConfidenceWebScanType(gofakeit.RandomString([]string{"Low", "Medium", "High", "FalsePositive"})),
			Solution:   generateRealisticSolution(template.name),
			Reference:  generateRealisticReference(template.name),
			CweID:      cweID,
			WascID:     "WASC-" + strconv.Itoa(gofakeit.Number(1, 49)), // WASC has 49 threat classifications
		}
		webVulns = append(webVulns, webVuln)
	}
	return webVulns
}

func generateInstancesWebVuln(sizeInstances int) []tools.InstanceAlert {
	instances := make([]tools.InstanceAlert, sizeInstances)
	methodNames := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	for i := 0; i < sizeInstances; i++ {
		instance := tools.InstanceAlert{
			ID:        strconv.Itoa(gofakeit.Number(1, 100)),
			URI:       gofakeit.URL(),
			Method:    enums.MethodType(methodNames[gofakeit.Number(0, 3)]),
			Param:     "JSESSIONID",
			Attack:    gofakeit.Question(),
			Evidence:  gofakeit.Comment(),
			OtherInfo: gofakeit.Comment(),
		}
		instances = append(instances, instance)
	}
	return instances
}

// generateRealisticSolution returns appropriate remediation guidance for common vulnerability types.
// Returns a generic security guidance message for unknown vulnerability types.
func generateRealisticSolution(vulnName string) string {
	solutions := map[string]string{
		"Cross Site Scripting":      "Encode all user input before rendering it in HTML context. Use Content Security Policy (CSP) headers. Validate and sanitize all input data.",
		"SQL Injection":             "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries. Apply principle of least privilege to database accounts.",
		"Command Injection":         "Avoid system calls with user input. If necessary, use strict input validation with allowlists. Use language-specific safe APIs instead of shell commands.",
		"Directory Traversal":       "Validate file paths against an allowlist. Use chroot jails or similar sandboxing. Normalize paths and reject those containing '..' sequences.",
		"CSRF":                      "Implement anti-CSRF tokens. Use SameSite cookie attribute. Verify referrer headers for state-changing operations.",
		"Sensitive Data Exposure":   "Encrypt sensitive data at rest and in transit. Use strong, up-to-date cryptographic algorithms. Implement proper key management.",
		"Security Misconfiguration": "Disable unnecessary features and services. Keep all software up to date. Review and harden all configuration settings.",
		"Broken Authentication":     "Implement multi-factor authentication. Use secure session management. Enforce strong password policies.",
		"Open Redirect":             "Validate redirect URLs against an allowlist. Avoid using user input directly in redirect locations.",
		"Remote File Inclusion":     "Disable remote file inclusion in configuration. Validate and sanitize all file paths. Use allowlists for acceptable file locations.",
	}

	if solution, exists := solutions[vulnName]; exists {
		return solution
	}
	return "Review and update the application to address this security vulnerability. Consult security best practices for your specific framework and technology stack."
}

// generateRealisticReference returns relevant OWASP reference URLs for common vulnerability types.
// Returns the OWASP Top 10 URL for unknown vulnerability types.
func generateRealisticReference(vulnName string) string {
	references := map[string]string{
		"Cross Site Scripting":      "https://owasp.org/www-community/attacks/xss/",
		"SQL Injection":             "https://owasp.org/www-community/attacks/SQL_Injection",
		"Command Injection":         "https://owasp.org/www-community/attacks/Command_Injection",
		"Directory Traversal":       "https://owasp.org/www-community/attacks/Path_Traversal",
		"CSRF":                      "https://owasp.org/www-community/attacks/csrf",
		"Sensitive Data Exposure":   "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
		"Security Misconfiguration": "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
		"Broken Authentication":     "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
		"Open Redirect":             "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
		"Remote File Inclusion":     "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion",
	}

	if reference, exists := references[vulnName]; exists {
		return reference
	}
	return "https://owasp.org/www-project-top-ten/"
}

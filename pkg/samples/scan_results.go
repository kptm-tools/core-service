package samples

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	whoisparser "github.com/likexian/whois-parser"
)

func generateEmails(size int) []string {
	emails := make([]string, size)
	for i := range size {
		emails[i] = gofakeit.Email()
	}
	return emails
}

func generateSubDomains(size int) []string {
	emails := make([]string, size)
	for i := range size {
		emails[i] = gofakeit.DomainName()
	}
	return emails
}

func generateInfoGather(toolName enums.ToolName, target enums.TargetType) tools.IToolResult {
	var result tools.IToolResult
	switch toolName {
	case enums.ToolWhoIs:
		if target == enums.IP {
			result = &tools.WhoIsResult{}
		} else {
			result = &tools.WhoIsResult{
				RawData: &whoisparser.WhoisInfo{
					Domain: &whoisparser.Domain{
						Domain: gofakeit.DomainName(),
					},
					Registrar: &whoisparser.Contact{
						Name:        gofakeit.Company(),
						ReferralURL: gofakeit.DomainName(),
					},
				},
			}
		}
	case enums.ToolHarvester:
		sizeEmail := 5
		if target == enums.IP {
			sizeEmail = 0
		}
		result = &tools.HarvesterResult{
			Emails:     generateEmails(gofakeit.Number(0, sizeEmail)),
			Subdomains: generateSubDomains(gofakeit.Number(0, sizeEmail)),
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

func SampleInformationGatheringScanResults(scans []domain.Scan) []domain.ScanResult {
	toolNames := make([]enums.ToolName, 3)
	toolNames[0] = enums.ToolDNSLookup
	toolNames[1] = enums.ToolHarvester
	toolNames[2] = enums.ToolWhoIs

	domainScanResult := make([]domain.ScanResult, len(toolNames)*len(scans))
	var indexSR int
	for _, scan := range scans {
		for _, tool := range toolNames {
			domainScanResult[indexSR] = *domain.NewScanResult(
				scan.ID,
				tools.ToolResult{
					Tool:      tool,
					Result:    generateInfoGather(tool, scan.Target.Type),
					Err:       nil,
					Timestamp: gofakeit.DateRange(scan.StartedAt, scan.UpdatedAt),
				},
			)
			indexSR++
		}
	}

	return domainScanResult
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

func generateVuln(size int, fromDate time.Time, cweDetails []tools.CWERemediation) []tools.Vulnerability {
	severityType, exploitableType, accessType, complexityType, privilegeRequiredType, likelihoodType, integrityImpact := generateDefaultEnumsVuln()

	vulns := make([]tools.Vulnerability, size)
	for i := range vulns {
		randomCWE := cweDetails[gofakeit.IntRange(0, len(cweDetails)-1)]
		vulns[i] = tools.Vulnerability{
			ID:                 uuid.New(),
			CveID:              "CVE-2020" + strconv.Itoa(gofakeit.Number(1, len(cweDetails))),
			Type:               enums.AllOwaspCategories[gofakeit.IntRange(0, len(enums.AllOwaspCategories)-1)],
			CWERemediation:     []tools.CWERemediation{randomCWE},
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

func generateNmapResult(scan domain.Scan, cweDetails []tools.CWERemediation) tools.NmapResult {

	return tools.NmapResult{
		HostName:     gofakeit.DomainName(),
		HostAddress:  gofakeit.IPv4Address(),
		MostLikelyOS: generateOSData(cweDetails),
		ScannedPorts: generatePortsData(gofakeit.Number(1, 10), *scan.EndedAt, cweDetails),
	}
}

func SampleNmapScanResults(scan domain.Scan, cweDetail []tools.CWERemediation) tools.NmapResult {
	return generateNmapResult(scan, cweDetail)
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
	webVulnNames := []string{
		"Cross Site Scripting",
		"SQL Injection",
		"Directory Traversal",
		"Remote File Inclusion",
		"Command Injection",
		"Open Redirect",
		"CSRF",
		"Sensitive Data Exposure",
		"Security Misconfiguration",
		"Broken Authentication",
	}

	sizeWebVulns := gofakeit.Number(1, len(webVulnNames))
	webVulns := make([]tools.WebVulnerability, 0, sizeWebVulns)
	gofakeit.ShuffleAnySlice(webVulnNames)
	for i := 0; i < sizeWebVulns; i++ {
		webVuln := tools.WebVulnerability{
			Name:       webVulnNames[i],
			Risk:       enums.RiskCodeType(gofakeit.RandomString([]string{"Low", "Medium", "High", "Informational"})),
			Instances:  generateInstancesWebVuln(gofakeit.Number(1, 50)),
			Confidence: enums.ConfidenceWebScanType(gofakeit.RandomString([]string{"Low", "Medium", "High", "FalsePositive"})),
			Solution:   gofakeit.LoremIpsumWord(),
			Reference:  gofakeit.URL(),
			CweID:      "CWE-" + strconv.Itoa(gofakeit.Number(1, 1000)),
			WascID:     "WASC-" + strconv.Itoa(gofakeit.Number(1, 100)),
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

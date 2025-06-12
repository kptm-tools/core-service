package samples

import (
	"math"
	"strconv"
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
			CveID:              "CVE-" + strconv.Itoa(gofakeit.Year()) + "-" + strconv.Itoa(gofakeit.Number(1, 30000)), // Example CVE for nginx
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
			Description:        gofakeit.LoremIpsumWord(),
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

func generatePortsData(size int, fromDate time.Time, cweDetails []tools.CWERemediation) []tools.PortData {
	status := make([]string, 2)
	status[0] = "open"
	status[1] = "closed"
	ports := make([]tools.PortData, size)
	for i := range ports {
		ports[i] = tools.PortData{
			ID:       uint16(gofakeit.IntRange(1, 100)),
			Protocol: "tcp",
			State:    status[gofakeit.Number(0, 1)],
			Service: tools.Service{
				Name:       "https",
				Version:    gofakeit.AppVersion(),
				Confidence: gofakeit.Number(1, 100),
			},
			Product:         "nginx",
			Vulnerabilities: generateVuln(gofakeit.IntRange(0, 10), fromDate, cweDetails),
		}
	}
	return ports
}

func generateNmapResult(scan domain.Scan, cweDetails []tools.CWERemediation) tools.NmapResult {
	return tools.NmapResult{
		HostName:    gofakeit.DomainName(),
		HostAddress: gofakeit.IPv4Address(),
		MostLikelyOS: tools.OSData{
			Name:            "Linux 3.x kernel",
			Accuracy:        gofakeit.Number(1, 10),
			CPE:             "cpe:2.3:o:f5:tmos:11.6:*:*:*:*:*:*:*",
			Vulnerabilities: generateVuln(4, time.Now(), cweDetails),
		},
		ScannedPorts: generatePortsData(gofakeit.Number(1, 10), *scan.EndedAt, cweDetails),
	}
}

func SampleNmapScanResults(scan domain.Scan, cweDetail []tools.CWERemediation) tools.NmapResult {
	return generateNmapResult(scan, cweDetail)
}

package samples

import (
	"github.com/brianvoe/gofakeit/v7"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	whoisparser "github.com/likexian/whois-parser"
	"math"
	"strconv"
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

func generateVuln(size int) []tools.Vulnerability {
	severityType := make([]enums.SeverityType, 6)
	severityType[0] = enums.SeverityTypeLow
	severityType[1] = enums.SeverityTypeMedium
	severityType[2] = enums.SeverityTypeHigh
	severityType[3] = enums.SeverityTypeUnknown
	severityType[4] = enums.SeverityTypeCritical
	severityType[5] = enums.SeverityTypeNone
	weaknessType := make([]enums.WeaknessType, 6)
	weaknessType[0] = enums.WeaknessInjection
	weaknessType[1] = enums.WeaknessInsecureDesign
	weaknessType[2] = enums.WeaknessOther
	weaknessType[3] = enums.WeaknessBrokenAccessControl
	weaknessType[4] = enums.WeaknessSecurityLoggingAndMonitoringFailures
	weaknessType[5] = enums.WeaknessNoInfo
	exploitableType := make([]enums.ExploitabilityType, 5)
	exploitableType[0] = enums.ExploitabilityTypeUndefined
	exploitableType[1] = enums.ExploitabilityTypeUnknown
	exploitableType[2] = enums.ExploitabilityTypeFunctional
	exploitableType[3] = enums.ExploitabilityTypeUnproven
	exploitableType[4] = enums.ExploitabilityTypeProofOfConcept
	vulns := make([]tools.Vulnerability, size)
	for i := range vulns {
		vulns[i] = tools.Vulnerability{
			ID:            "CVE-" + strconv.Itoa(gofakeit.Year()) + "-" + strconv.Itoa(gofakeit.Number(1, 30000)), // Example CVE for nginx
			Type:          weaknessType[gofakeit.IntRange(0, len(weaknessType)-1)],
			BaseCVSSScore: math.Trunc(gofakeit.Float64Range(0, 10)*10) / 10,
			BaseSeverity:  severityType[gofakeit.IntRange(0, 5)],
			References:    []string{gofakeit.URL()},
			Exploit: tools.Exploit{
				Score:          math.Trunc(gofakeit.Float64Range(0, 1)*10) / 10,
				Exploitability: exploitableType[gofakeit.IntRange(0, len(exploitableType)-1)],
			},
		}
	}
	return vulns
}

func generatePortsData(size int) []tools.PortData {
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
			Vulnerabilities: generateVuln(gofakeit.IntRange(0, 10)),
		}
	}
	return ports
}

func generateNmapResult() tools.IToolResult {
	return &tools.NmapResult{
		HostName:    gofakeit.DomainName(),
		HostAddress: gofakeit.IPv4Address(),
		MostLikelyOS: tools.OSData{
			Name:     "Linux 3.x kernel",
			Accuracy: gofakeit.Number(1, 10),
			CPE:      "cpe:2.3:o:f5:tmos:11.6:*:*:*:*:*:*:*",
		},
		ScannedPorts: generatePortsData(gofakeit.Number(1, 10)),
	}
}

func SampleVulnerabilityAnalysisScanResults(scans []domain.Scan) []domain.ScanResult {
	domainScanResult := make([]domain.ScanResult, len(scans))
	for i, scan := range scans {
		domainScanResult[i] = domain.ScanResult{
			ScanID:    scan.ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: gofakeit.DateRange(scan.StartedAt, scan.UpdatedAt),
			Result: tools.ToolResult{
				Tool:   enums.ToolNmap,
				Result: generateNmapResult(),
			},
		}
	}
	return domainScanResult
}

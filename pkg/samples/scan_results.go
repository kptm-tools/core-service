package samples

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	whoisparser "github.com/likexian/whois-parser"
)

func SampleInformationGatheringScanResults(scans []domain.Scan) []domain.ScanResult {
	currentYear := time.Now().Year()

	month1 := time.Month(1) // January (First semester)
	month2 := time.Month(5) // May (First semester)
	month3 := time.Month(8) // August (Second semester)

	return []domain.ScanResult{
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Registrar: &whoisparser.Contact{
							Name:    "John Doe",
							Street:  "Sesame Street",
							Country: "United States of America",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool:      enums.ToolDNSLookup,
				Result:    &tools.DNSLookupResult{},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{"john@example.com", "mary@example.com"},
					Subdomains: []string{"www.example.com", "ftp.example.com"},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Results for month2
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Registrar: &whoisparser.Contact{
							Name:    "John Doe",
							Street:  "Sesame Street",
							Country: "United States of America",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool:      enums.ToolDNSLookup,
				Result:    &tools.DNSLookupResult{},
				Err:       nil,
				Timestamp: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{"john@example.com", "mary@example.com"},
					Subdomains: []string{"www.example.com", "ftp.example.com"},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Results for month3
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Registrar: &whoisparser.Contact{
							Name:    "John Doe",
							Street:  "Sesame Street",
							Country: "United States of America",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool:      enums.ToolDNSLookup,
				Result:    &tools.DNSLookupResult{},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{},
					Subdomains: []string{},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// scans[1] Results
		// results for month1
		*domain.NewScanResult(
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Registrar: &whoisparser.Contact{
							Name:    "John Doe",
							Street:  "Sesame Street",
							Country: "United States of America",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[1].ID,
			tools.ToolResult{
				Tool:      enums.ToolDNSLookup,
				Result:    &tools.DNSLookupResult{},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{"john@example.com", "mary@example.com"},
					Subdomains: []string{"www.example.com", "ftp.example.com"},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Results for month3
		*domain.NewScanResult(
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Registrar: &whoisparser.Contact{
							Name:    "John Doe",
							Street:  "Sesame Street",
							Country: "United States of America",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[1].ID,
			tools.ToolResult{
				Tool:      enums.ToolDNSLookup,
				Result:    &tools.DNSLookupResult{},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult(
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{},
					Subdomains: []string{},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
	}
}

func SampleVulnerabilityAnalysisScanResults(scans []domain.Scan) []domain.ScanResult {
	currentYear := time.Now().Year()

	month1 := time.Month(1) // January (First semester)
	month2 := time.Month(5) // May (First semester)
	month3 := time.Month(8) // August (Second semester)

	return []domain.ScanResult{
		// scans[0] results
		// Month 1 scan
		{
			ScanID:    scans[0].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),

			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:     "example.com",
					HostAddress:  "192.168.0.0",
					MostLikelyOS: "Linux 3.x kernel",
					ScannedPorts: []tools.PortData{
						{
							ID:       80,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http",
								Version:    "Apache httpd 2.4.6",
								Confidence: 95,
							},
							Product: "Apache httpd",
							Vulnerabilities: []tools.Vulnerability{
								{
									ID:          "CVE-2017-15715",
									Type:        "cve",
									CVSS:        9.8,
									References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploitable: true,
								},
							},
						},
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3",
								Confidence: 90,
							},
							Product:         "nginx",
							Vulnerabilities: []tools.Vulnerability{}, // No vulnerabilities for this port in this example
						},
						{
							ID:       22,
							Protocol: "tcp",
							State:    "closed",
							Service: tools.Service{
								Name:       "ssh",
								Version:    "", // Unknown version as port is closed
								Confidence: 85,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
					},
				},
			},
		},

		// Month 2 scan
		{
			ScanID:    scans[0].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),

			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:     "example.com",
					HostAddress:  "192.168.0.0",
					MostLikelyOS: "Linux 3.x kernel",
					ScannedPorts: []tools.PortData{
						{
							ID:       80,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http",
								Version:    "Apache httpd 2.4.6",
								Confidence: 95,
							},
							Product: "Apache httpd",
							Vulnerabilities: []tools.Vulnerability{
								{
									ID:          "CVE-2017-15715",
									Type:        "cve",
									CVSS:        9.8,
									References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploitable: true,
								},
							},
						},
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3",
								Confidence: 90,
							},
							Product:         "nginx",
							Vulnerabilities: []tools.Vulnerability{}, // No vulnerabilities for this port in this example
						},
					},
				},
			},
		},

		// Month 3 scan
		{
			ScanID:    scans[0].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),

			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:     "example.com",
					HostAddress:  "192.168.0.0",
					MostLikelyOS: "Linux 3.x kernel",
					ScannedPorts: []tools.PortData{
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3",
								Confidence: 90,
							},
							Product:         "nginx",
							Vulnerabilities: []tools.Vulnerability{}, // No vulnerabilities for this port in this example
						},
					},
				},
			},
		},

		// scans[1] results
		// Month 1 scan
		{
			ScanID:    scans[1].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),

			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:     "example.com",
					HostAddress:  "192.168.0.0",
					MostLikelyOS: "Linux 3.x kernel",
					ScannedPorts: []tools.PortData{
						{
							ID:       80,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http",
								Version:    "Apache httpd 2.4.6",
								Confidence: 95,
							},
							Product: "Apache httpd",
							Vulnerabilities: []tools.Vulnerability{
								{
									ID:          "CVE-2017-15715",
									Type:        "cve",
									CVSS:        9.8,
									References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploitable: true,
								},
								{
									ID:          "CVE-2017-15716",
									Type:        "cve",
									CVSS:        5.8,
									References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploitable: true,
								},
								{
									ID:          "CVE-2017-15717",
									Type:        "cve",
									CVSS:        3.8,
									References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploitable: true,
								},
							},
						},
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3",
								Confidence: 90,
							},
							Product:         "nginx",
							Vulnerabilities: []tools.Vulnerability{}, // No vulnerabilities for this port in this example
						},
						{
							ID:       22,
							Protocol: "tcp",
							State:    "closed",
							Service: tools.Service{
								Name:       "ssh",
								Version:    "", // Unknown version as port is closed
								Confidence: 85,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
					},
				},
			},
		},

		// Month 3 scan
		{
			ScanID:    scans[1].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),

			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:     "example.com",
					HostAddress:  "192.168.0.0",
					MostLikelyOS: "Linux 3.x kernel",
					ScannedPorts: []tools.PortData{
						{
							ID:       80,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http",
								Version:    "Apache httpd 2.4.6",
								Confidence: 95,
							},
							Product: "Apache httpd",
							Vulnerabilities: []tools.Vulnerability{
								{
									ID:          "CVE-2017-15715",
									Type:        "cve",
									CVSS:        9.8,
									References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploitable: true,
								},
							},
						},
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3",
								Confidence: 90,
							},
							Product:         "nginx",
							Vulnerabilities: []tools.Vulnerability{}, // No vulnerabilities for this port in this example
						},
					},
				},
			},
		},
	}
}

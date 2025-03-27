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

	month1 := time.Month(1)  // January
	month2 := time.Month(3)  // March
	month3 := time.Month(5)  // May
	month4 := time.Month(7)  // July
	month5 := time.Month(9)  // September
	month6 := time.Month(11) // November

	return []domain.ScanResult{
		// Scan 1: example.com - January results
		*domain.NewScanResult( // Whois - Scan 1 - Month 1
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Domain: &whoisparser.Domain{
							Domain: "example.com",
						},
						Registrar: &whoisparser.Contact{
							Name:        "Example Registrar, Inc.",
							ReferralURL: "www.example-registrar.com",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // DNSLookup - Scan 1 - Month 1
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: &tools.DNSLookupResult{
					Domain: "example.com",
					DNSRecords: []tools.DNSRecord{
						{
							Type:  tools.ARecord,
							Value: "192.0.2.50",
						},
						{
							Type:  tools.AAAARecord,
							Value: "",
						},
						{
							Type:  tools.CNAMERecord,
							Value: "example.com",
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
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Harvester - Scan 1 - Month 1
			scans[0].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{"info@example.com", "sales@example.com"},
					Subdomains: []string{"blog.example.com", "api.example.com"},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Scan 2: example.com - March results (some changes from Jan)
		*domain.NewScanResult( // Whois - Scan 2 - Month 2
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Domain: &whoisparser.Domain{
							Domain: "example.com",
						},
						Registrar: &whoisparser.Contact{
							Name:        "Example Registrar, Inc.", // Same registrar
							ReferralURL: "www.example-registrar.com",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // DNSLookup - Scan 2 - Month 2 (no changes)
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: &tools.DNSLookupResult{
					Domain: "example.com",
					DNSRecords: []tools.DNSRecord{
						{
							Type:  tools.ARecord,
							Value: "192.0.2.50",
						},
						{
							Type:  tools.AAAARecord,
							Value: "",
						},
						{
							Type:  tools.CNAMERecord,
							Value: "example.com",
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
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Harvester - Scan 2 - Month 2 (new subdomain found)
			scans[1].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{"info@example.com", "sales@example.com", "admin@example.com"}, // New email
					Subdomains: []string{"blog.example.com", "api.example.com", "cdn.example.com"},     // New subdomain
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Scan 3: anothersample.net - May results (different domain)
		*domain.NewScanResult( // Whois - Scan 3 - Month 3
			scans[2].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Domain: &whoisparser.Domain{
							Domain: "anothersample.net",
						},
						Registrar: &whoisparser.Contact{
							Name:        "Another Registrar LLC",
							ReferralURL: "www.another-registrar.net",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // DNSLookup - Scan 3 - Month 3 (different IPs/NS)
			scans[2].ID,
			tools.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: &tools.DNSLookupResult{
					Domain: "example.com",
					DNSRecords: []tools.DNSRecord{
						{
							Type:  tools.ARecord,
							Value: "192.0.2.50",
						},
						{
							Type:  tools.AAAARecord,
							Value: "",
						},
						{
							Type:  tools.CNAMERecord,
							Value: "example.com",
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
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Harvester - Scan 3 - Month 3 (fewer results)
			scans[2].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{"contact@anothersample.net"}, // Fewer emails
					Subdomains: []string{},                            // No subdomains found
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Scan 4: test-host.org - July results (another new domain, even fewer results)
		*domain.NewScanResult( // Whois - Scan 4 - Month 4
			scans[3].ID,
			tools.ToolResult{
				Tool: enums.ToolWhoIs,
				Result: &tools.WhoIsResult{
					RawData: &whoisparser.WhoisInfo{
						Domain: &whoisparser.Domain{
							Domain: "test-host.org",
						},
						Registrar: &whoisparser.Contact{
							Name:        "Test Registrar Group",
							ReferralURL: "www.test-registrar.info",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month4, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // DNSLookup - Scan 4 - Month 4 (minimal DNS records)
			scans[3].ID,
			tools.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: &tools.DNSLookupResult{
					Domain: "test-host.org",
					DNSRecords: []tools.DNSRecord{
						{
							Type:  tools.ARecord,
							Value: "192.0.2.50",
						},
						{
							Type:  tools.AAAARecord,
							Value: "",
						},
						{
							Type:  tools.CNAMERecord,
							Value: "example.com",
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
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month4, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Harvester - Scan 4 - Month 4 (no results)
			scans[3].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{}, // Empty results
					Subdomains: []string{},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month4, 15, 10, 0, 0, 0, time.UTC),
			},
		),

		// Scan 5: subdomain.example.com - September results (subdomain results)
		*domain.NewScanResult( // Whois - Scan 5 - Month 5 (whois often not available for subdomains)
			scans[4].ID,
			tools.ToolResult{
				Tool:      enums.ToolWhoIs,
				Result:    &tools.WhoIsResult{}, // Empty Whois result - common for subdomains
				Err:       nil,
				Timestamp: time.Date(currentYear, month5, 10, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // DNSLookup - Scan 5 - Month 5 (CNAME and A records for subdomain)
			scans[4].ID,
			tools.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: &tools.DNSLookupResult{
					Domain: "test-host.org",
					DNSRecords: []tools.DNSRecord{
						{
							Type:  tools.ARecord,
							Value: "192.0.2.50",
						},
						{
							Type:  tools.AAAARecord,
							Value: "",
						},
						{
							Type:  tools.CNAMERecord,
							Value: "example.com",
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
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month5, 10, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Harvester - Scan 5 - Month 5 (limited subdomain harvesting)
			scans[4].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{},                                // Fewer emails for subdomain
					Subdomains: []string{"another.subdomain.example.com"}, // Sub-subdomain found
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month5, 10, 10, 0, 0, 0, time.UTC),
			},
		),

		// Scan 6: 192.168.1.1 - November results (IP address target - different tools might be relevant)
		*domain.NewScanResult( // DNSLookup - Scan 6 - Month 6 (Reverse DNS Lookup)
			scans[5].ID,
			tools.ToolResult{
				Tool: enums.ToolDNSLookup,
				Result: &tools.DNSLookupResult{
					Domain: "subdomain.example.com",
					DNSRecords: []tools.DNSRecord{
						{
							Type:  tools.TXTRecord,
							Value: "printer.local",
						},
					},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month6, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Whois - Scan 6 - Month 6 (Whois not applicable to IP)
			scans[5].ID,
			tools.ToolResult{
				Tool:      enums.ToolWhoIs,
				Result:    &tools.WhoIsResult{}, // Empty Whois result - not applicable for IP
				Err:       nil,
				Timestamp: time.Date(currentYear, month6, 15, 10, 0, 0, 0, time.UTC),
			},
		),
		*domain.NewScanResult( // Harvester - Scan 6 - Month 6 (Harvester less relevant for direct IP)
			scans[5].ID,
			tools.ToolResult{
				Tool: enums.ToolHarvester,
				Result: &tools.HarvesterResult{
					Emails:     []string{}, // Likely empty for IP
					Subdomains: []string{},
				},
				Err:       nil,
				Timestamp: time.Date(currentYear, month6, 15, 10, 0, 0, 0, time.UTC),
			},
		),
	}
}

func SampleVulnerabilityAnalysisScanResults(scans []domain.Scan) []domain.ScanResult {
	currentYear := time.Now().Year()

	month1 := time.Month(1)  // January
	month2 := time.Month(3)  // March
	month3 := time.Month(5)  // May
	month4 := time.Month(7)  // July
	month5 := time.Month(9)  // September
	month6 := time.Month(11) // November

	return []domain.ScanResult{
		// Vulnerability results for example.com (scans[0] and scans[1])

		// Scan 1: example.com - January vulnerability results
		{ // Nmap - Scan 1 - Month 1
			ScanID:    scans[0].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month1, 15, 10, 0, 0, 0, time.UTC),
			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:    "example.com",
					HostAddress: "192.0.2.1", // Corrected IP to match DNSLookup results
					MostLikelyOS: tools.OSData{
						Name:     "Linux 3.x kernel",
						Accuracy: 7,
						CPE:      "cpe:2.3:o:f5:tmos:11.6:*:*:*:*:*:*:*",
					},
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
									ID:            "CVE-2017-15715",
									Type:          enums.WeaknessInjection,
									BaseCVSSScore: 9.8,
									BaseSeverity:  enums.SeverityTypeCritical,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploit: tools.Exploit{
										Score:          9.8,
										Exploitability: enums.ExploitabilityTypeHigh,
									},
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
							Vulnerabilities: []tools.Vulnerability{}, // No vulnerabilities for HTTPS in Jan
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

		// Scan 2: example.com - March vulnerability results (new vulnerabilities on HTTPS)
		{ // Nmap - Scan 2 - Month 2
			ScanID:    scans[1].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month2, 15, 10, 0, 0, 0, time.UTC),
			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:    "example.com",
					HostAddress: "192.0.2.1", // IP consistent
					MostLikelyOS: tools.OSData{
						Name:     "Linux 3.x kernel",
						Accuracy: 7,
						CPE:      "cpe:2.3:o:f5:tmos:11.6:*:*:*:*:*:*:*",
					},
					ScannedPorts: []tools.PortData{
						{
							ID:       80,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http",
								Version:    "Apache httpd 2.4.6", // Version unchanged
								Confidence: 95,
							},
							Product: "Apache httpd",
							Vulnerabilities: []tools.Vulnerability{ // Vulnerability still present
								{
									ID:            "CVE-2017-15715",
									Type:          enums.WeaknessInjection,
									BaseCVSSScore: 9.8,
									BaseSeverity:  enums.SeverityTypeCritical,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-15715"},
									Exploit: tools.Exploit{
										Score:          0.8,
										Exploitability: enums.ExploitabilityTypeUnproven,
									},
								},
							},
						},
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3", // Version unchanged
								Confidence: 90,
							},
							Product: "nginx",
							Vulnerabilities: []tools.Vulnerability{ // New vulnerabilities on HTTPS
								{
									ID:            "CVE-2021-34527", // Example CVE for nginx
									Type:          enums.WeaknessBrokenAccessControl,
									BaseCVSSScore: 7.5,
									BaseSeverity:  enums.SeverityTypeHigh,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-34527"},
									Exploit: tools.Exploit{
										Score:          0.8,
										Exploitability: enums.ExploitabilityTypeUnproven,
									},
								},
								{
									ID:            "CVE-2021-34528", // Another example CVE for nginx
									Type:          enums.WeaknessInsecureDesign,
									BaseCVSSScore: 6.5,
									BaseSeverity:  enums.SeverityTypeMedium,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-34528"},
									Exploit: tools.Exploit{
										Score:          0.0,
										Exploitability: enums.ExploitabilityTypeProofOfConcept,
									},
								},
							},
						},
						{
							ID:       22,
							Protocol: "tcp",
							State:    "closed",
							Service: tools.Service{
								Name:       "ssh",
								Version:    "",
								Confidence: 85,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
					},
				},
			},
		},

		// Scan 3: anothersample.net - May vulnerability results (different host, different services)
		{ // Nmap - Scan 3 - Month 3
			ScanID:    scans[2].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month3, 15, 10, 0, 0, 0, time.UTC),
			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:    "anothersample.net",
					HostAddress: "203.0.113.10", // Corrected IP to match DNSLookup
					MostLikelyOS: tools.OSData{
						Name:     "Windows Server 2019",
						CPE:      "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:datacenter:*:x86:*",
						Accuracy: 10,
					},
					ScannedPorts: []tools.PortData{
						{
							ID:       80,
							Protocol: "tcp",
							State:    "closed", // Port 80 closed on this host
							Service: tools.Service{
								Name:       "http",
								Version:    "",
								Confidence: 70,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "IIS 10.0", // Different web server
								Confidence: 92,
							},
							Product: "Microsoft IIS",
							Vulnerabilities: []tools.Vulnerability{ // Different vulnerabilities
								{
									ID:            "CVE-2020-0601", // Example CVE for IIS
									Type:          enums.WeaknessSecurityMisconfiguration,
									BaseCVSSScore: 8.8,
									BaseSeverity:  enums.SeverityTypeHigh,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-0601"},
									Exploit: tools.Exploit{
										Score:          9.9,
										Exploitability: enums.ExploitabilityTypeHigh,
									},
								},
							},
						},
						{
							ID:       3389, // RDP port
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "ms-wbt-server", // RDP service
								Version:    "",              // Version not always detectable
								Confidence: 88,
							},
							Product:         "Microsoft Terminal Services",
							Vulnerabilities: []tools.Vulnerability{}, // No vulns on RDP for this example
						},
					},
				},
			},
		},

		// Scan 4: test-host.org - July vulnerability results (minimal open ports)
		{ // Nmap - Scan 4 - Month 4
			ScanID:    scans[3].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month4, 15, 10, 0, 0, 0, time.UTC),
			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:    "test-host.org",
					HostAddress: "10.0.0.5", // Private IP consistent with DNS
					MostLikelyOS: tools.OSData{
						Name:     "Embedded Linux",
						CPE:      "cpe:2.3:o:nvidia:jetson_linux:32.2:*:*:*:*:*:*:*",
						Accuracy: 10,
					},
					ScannedPorts: []tools.PortData{ // Minimal open ports
						{
							ID:       8080, // Example of non-standard HTTP port
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http-proxy", // Example of service on unusual port
								Version:    "lighttpd",
								Confidence: 80,
							},
							Product:         "lighttpd",
							Vulnerabilities: []tools.Vulnerability{}, // No vulns for this example
						},
						{
							ID:       21,
							Protocol: "tcp",
							State:    "closed",
							Service: tools.Service{
								Name:       "ftp",
								Version:    "",
								Confidence: 75,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
					},
				},
			},
		},

		// Scan 5: subdomain.example.com - September vulnerability results (inherit vulns from main domain OR different)
		{ // Nmap - Scan 5 - Month 5
			ScanID:    scans[4].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month5, 15, 10, 0, 0, 0, time.UTC),
			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:    "subdomain.example.com",
					HostAddress: "192.0.2.50", // IP from DNS lookup
					MostLikelyOS: tools.OSData{
						Name:     "Linux 3.x kernel",
						CPE:      "cpe:2.3:o:linux:linux_kernel:3.10.0:*:*:*:*:*:arm64:*",
						Accuracy: 10,
					},
					ScannedPorts: []tools.PortData{ // Subdomain might have different open ports
						{
							ID:       443,
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "https",
								Version:    "nginx 1.10.3", // Same version as main domain in Jan/Mar
								Confidence: 90,
							},
							Product: "nginx",
							Vulnerabilities: []tools.Vulnerability{ // Could inherit same vulns
								{
									ID:            "CVE-2021-34527",
									Type:          enums.WeaknessOther,
									BaseCVSSScore: 7.5,
									BaseSeverity:  enums.SeverityTypeHigh,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-34527"},
									Exploit: tools.Exploit{
										Score:          9.9,
										Exploitability: enums.ExploitabilityTypeHigh,
									},
								},
								{
									ID:            "CVE-2021-34528",
									Type:          enums.WeaknessNoInfo,
									BaseCVSSScore: 6.5,
									BaseSeverity:  enums.SeverityTypeMedium,
									References:    []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-34528"},
									Exploit: tools.Exploit{
										Score:          5.0,
										Exploitability: enums.ExploitabilityTypeFunctional,
									},
								},
							},
						},
						{
							ID:       80, // HTTP might be closed on subdomain
							Protocol: "tcp",
							State:    "closed",
							Service: tools.Service{
								Name:       "http",
								Version:    "",
								Confidence: 70,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
					},
				},
			},
		},

		// Scan 6: 192.168.1.1 - November vulnerability results (IP target - different port profile)
		{ // Nmap - Scan 6 - Month 6
			ScanID:    scans[5].ID,
			ToolName:  enums.ToolNmap.String(),
			Success:   true,
			CreatedAt: time.Date(currentYear, month6, 15, 10, 0, 0, 0, time.UTC),
			Result: tools.ToolResult{
				Tool: enums.ToolNmap,
				Result: &tools.NmapResult{
					HostName:    "printer.local", // PTR from DNSLookup result
					HostAddress: "192.168.1.1",   // IP target
					MostLikelyOS: tools.OSData{
						Name:     "Windows XP Embedded",
						CPE:      "cpe:2.3:o:microsoft:windows_xp:-:sp3:*:*:embedded:*:x64:*",
						Accuracy: 10,
					},
					ScannedPorts: []tools.PortData{ // Different ports for a device
						{
							ID:       9100, // Printer port
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "jetdirect", // Printer service
								Version:    "",          // Version often not detectable
								Confidence: 85,
							},
							Product:         "HP JetDirect",
							Vulnerabilities: []tools.Vulnerability{}, // No vulns example
						},
						{
							ID:       80, // HTTP interface for printer
							Protocol: "tcp",
							State:    "open",
							Service: tools.Service{
								Name:       "http",
								Version:    "Simple embedded httpd", // Example embedded httpd
								Confidence: 78,
							},
							Product: "Embedded HTTP Server",
							Vulnerabilities: []tools.Vulnerability{
								{
									ID:            "CVE-2023-XXXXX", // Placeholder CVE for embedded device
									Type:          enums.WeaknessNoInfo,
									BaseCVSSScore: 6.0,
									BaseSeverity:  enums.SeverityTypeMedium,
									References:    []string{"https://example.com/embedded-cve"}, // Placeholder URL
									Exploit: tools.Exploit{
										Score:          5.0,
										Exploitability: enums.ExploitabilityTypeProofOfConcept,
									},
								},
							},
						},
						{
							ID:       443, // HTTPS - maybe for device management
							Protocol: "tcp",
							State:    "closed",
							Service: tools.Service{
								Name:       "https",
								Version:    "",
								Confidence: 70,
							},
							Product:         "",
							Vulnerabilities: []tools.Vulnerability{},
						},
					},
				},
			},
		},
	}
}

package dto

import (
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type HarvesterResultDTO struct {
	Emails     []string `json:"emails"`
	Subdomains []string `json:"subdomains"`
}

type WhoIsDomain struct {
	Name        string   `json:"domain"`
	NameServers []string `json:"name_servers"`
}

type WhoIsRegistrar struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type WhoIsRegistrant struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
}

// WhoisResultDTO defines the public structure for Whois findings.
type WhoisResultDTO struct {
	Domain     WhoIsDomain     `json:"domain"`
	Registrar  WhoIsRegistrar  `json:"registrar"`
	Registrant WhoIsRegistrant `json:"registrant"`
}

// DNSLookupResultDTO defines the public structure for DNS Lookup findings.
type DNSLookupResultDTO struct {
	Domain        string         `json:"domain"`
	DNSRecords    []DNSRecordDTO `json:"dns_records"`
	DNSSECEnabled bool           `json:"dnssec_enabled"`
}

// DNSRecordDTO represents a single DNS record for the API.
type DNSRecordDTO struct {
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

// ScanInformationGatheredDTO aggregates all reconnaissance tool results for a scan.
// It uses pointers to the new, independent DTOs.
type ScanInformationGatheredDTO struct {
	HarvesterResult *HarvesterResultDTO `json:"harvester_result,omitempty"`
	WhoisResult     *WhoisResultDTO     `json:"whois_result,omitempty"`
	DNSLookupResult *DNSLookupResultDTO `json:"dns_lookup_result,omitempty"`
}

func ConvertScanResultDomToDtoScanInformationGathered(results []domain.ScanResult) *ScanInformationGatheredDTO {
	response := &ScanInformationGatheredDTO{}
	for _, scanResult := range results {
		switch scanResult.ToolName {
		case enums.ToolHarvester.String():
			if !scanResult.Success {
				response.HarvesterResult = nil
			} else {
				// Cast IToolResult to *tools.HarvesterResult
				if harvester, ok := scanResult.Result.Result.(*tools.HarvesterResult); ok && harvester != nil {
					response.HarvesterResult = &HarvesterResultDTO{
						Emails:     harvester.Emails,
						Subdomains: harvester.Subdomains,
					}
				} else {
					response.HarvesterResult = nil
				}
			}

		case enums.ToolWhoIs.String():
			if !scanResult.Success {
				response.WhoisResult = nil
			} else {
				// Cast IToolResult to *tools.WhoIsResult
				if whois, ok := scanResult.Result.Result.(*tools.WhoIsResult); ok && whois != nil {
					var domain WhoIsDomain
					if whois.RawData != nil && whois.RawData.Domain != nil {
						domain = WhoIsDomain{
							Name:        whois.RawData.Domain.Domain,
							NameServers: whois.RawData.Domain.NameServers,
						}
					} else {
						domain = WhoIsDomain{}
					}

					var registrar WhoIsRegistrar
					if whois.RawData != nil && whois.RawData.Registrar != nil {
						registrar = WhoIsRegistrar{
							Name:  whois.RawData.Registrar.Name,
							Email: whois.RawData.Registrar.Email,
						}
					} else {
						registrar = WhoIsRegistrar{}
					}

					var registrant WhoIsRegistrant
					if whois.RawData != nil && whois.RawData.Registrant != nil {
						registrant = WhoIsRegistrant{
							Name:         whois.RawData.Registrant.Name,
							Organization: whois.RawData.Registrant.Organization,
						}
					} else {
						registrant = WhoIsRegistrant{}
					}

					response.WhoisResult = &WhoisResultDTO{
						Domain:     domain,
						Registrar:  registrar,
						Registrant: registrant,
					}
				} else {
					response.WhoisResult = nil
				}
			}
		case enums.ToolDNSLookup.String():
			if !scanResult.Success {
				response.DNSLookupResult = nil
			} else {
				if dnsLookup, ok := scanResult.Result.Result.(*tools.DNSLookupResult); ok && dnsLookup != nil {
					dnsRecords := make([]DNSRecordDTO, 0, len(dnsLookup.DNSRecords))
					for _, rec := range dnsLookup.DNSRecords {
						dnsRecords = append(dnsRecords, DNSRecordDTO{
							Type:  string(rec.Type),
							Value: rec.Value,
						})
					}
					response.DNSLookupResult = &DNSLookupResultDTO{
						Domain:        dnsLookup.Domain,
						DNSRecords:    dnsRecords,
						DNSSECEnabled: dnsLookup.DNSSECEnabled,
					}
				} else {
					response.DNSLookupResult = nil
				}
			}
		}
	}
	return response
}

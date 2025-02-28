package handlers

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type RegisterTenantResponse struct {
	ApplicationID string      `json:"application_id"`
	User          domain.User `json:"user"`
}

type ScanVulnerabilitySummaryResponse struct {
	ScanID                    string                      `json:"scan_id"`
	Domain                    string                      `json:"domain"`
	GeneralSummary            VulnerabilityGeneralSummary `json:"general_summary"`
	VulnerabilitiesByCategory VulnerabilitiesByCategory   `json:"vulnerabilities_by_category"`
	VulnerabilityTrends       VulnerabilityTrends         `json:"vulnerability_trends"`
}

type VulnerabilityGeneralSummary struct {
	TotalVulnerabilities int                  `json:"total_vulnerabilities"`
	SeverityCounts       tools.SeverityCounts `json:"severity_counts,omitempty"`
}

type VulnerabilitiesByCategory struct {
	CategoryData []CategoryData `json:"category_data"`
}

type CategoryData struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

type VulnerabilityTrends struct {
	TimePeriods               []TimePeriod `json:"time_periods"`
	AverageVulnerabilityCount float64      `json:"average_vulnerability_count"`
}

type TimePeriod struct {
	TimePeriod         string `json:"time_period"`
	VulnerabilityCount int    `json:"vulnerability_count"`
}

func adaptCategoryData(serviceCategoryData []domain.ServiceCategoryData) []CategoryData {
	adaptedData := make([]CategoryData, len(serviceCategoryData))
	for i, svcData := range serviceCategoryData {
		adaptedData[i] = CategoryData{
			Category: svcData.Category,
			Count:    svcData.Count,
		}
	}
	return adaptedData
}

func adaptTimePeriods(serviceTimePeriodData []domain.ServiceTimePeriod) []TimePeriod {
	adaptedData := make([]TimePeriod, len(serviceTimePeriodData))
	for i, svcData := range serviceTimePeriodData {
		adaptedData[i] = TimePeriod{
			TimePeriod:         svcData.TimePeriod,
			VulnerabilityCount: svcData.VulnerabilityCount,
		}
	}
	return adaptedData
}

type ReportsResponse struct {
	ScanID          string    `json:"scan_id"`
	Domain          string    `json:"domain"`
	IP              string    `json:"ip"`
	ScanDate        time.Time `json:"scan_date"`
	TotalSeverities int       `json:"total_severities"`
	CommentStatus   string    `json:"comment_status"`
}

// ScoreCardTrendResponse is the DTO for the scorecard trend data for a single host
type ScoreCardTrendResponse struct {
	Alias            string   `json:"alias" example:"Ovofinance 2"`
	OldestScore      *float64 `json:"oldest_score" example:"71.0"`
	LatestScore      *float64 `json:"latest_score" example:"0.59"`
	LatestScoreGrade *string  `json:"latest_score_grade"`
}

// ScanVulnerabilityItemsResponse is the DTO for the list of Vulnerabilities
// associated to a scan.
type ScanVulnerabilityItemsResponse struct {
	ScanDate             time.Time               `json:"scan_date"`
	Alias                string                  `json:"alias"`
	TotalVulnerabilities int                     `json:"total_vulnerabilities"`
	SeverityCounts       tools.SeverityCounts    `json:"severity_counts,omitempty"`
	Vulnerabilities      []ScanVulnerabilityItem `json:"vulnerabilities"`
}

type ScanVulnerabilityItem struct {
	ID             int      `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	MaxCVSS        float64  `json:"max_cvss"`
	RiskScore      float64  `json:"risk_score"`
	ImpactScore    float64  `json:"impact_score"`
	Likelihood     string   `json:"likelihood"`
	Access         string   `json:"access"`
	Complexity     string   `json:"complexity"`
	Privileges     string   `json:"privileges"`
	Exploitability string   `json:"exploitability"`
	Description    string   `json:"description"`
	Comment        string   `json:"comment"`
	References     []string `json:"references"`
}

// ScanVulnerabilityDetailResponse is the DTO with the details for a particular
// scan's vulenrability.
type ScanVulnerabilityDetailResponse struct {
	ID       int       `json:"id"`
	ScanDate time.Time `json:"scan_date"`

	Host HostItem  `json:"host"`
	Port *PortItem `json:"port,omitempty"`
	OS   *OSItem   `json:"operating_system,omitempty"`

	Name           string  `json:"name"`
	Severity       string  `json:"severity"`
	MaxCVSS        float64 `json:"max_cvss"`
	RiskScore      float64 `json:"risk_score"`
	ImpactScore    float64 `json:"impact_score"`
	Likelihood     string  `json:"likelihood"`
	Access         string  `json:"access"`
	Complexity     string  `json:"complexity"`
	Privileges     string  `json:"privileges"`
	Exploitability string  `json:"exploitability"`

	Description    string   `json:"description"`
	Comment        string   `json:"comment"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references"`

	DateInfo   DateInfo   `json:"date"`
	PluginInfo PluginInfo `json:"plugin"`
	VPRKeyD    VPRKeyInfo `json:"vpr_key_d"`
	RiskInfo   RiskInfo   `json:"risk"`
}

type HostItem struct {
	Alias     string `json:"alias"`
	IPAddress string `json:"ip_address"`
}

type PortItem struct {
	ID       uint16 `json:"id"`
	Protocol string `json:"protocol"`
}

type OSItem struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type DateInfo struct {
	Published   time.Time `json:"published"`
	LastUpdated time.Time `json:"last_updated"`
}

// PluginInfo refers to info about the service/operating system
// associated with the vulnerability
type PluginInfo struct {
	CPE      string `json:"cpe"` // CPE
	Severity string `json:"severity"`
	Version  string `json:"version"`
	Type     string `json:"type"`   // AccessType
	Family   string `json:"family"` // OS = family, Sevice = Product
}

type VPRKeyInfo struct {
	ThreatIntensity string `json:"threat_intensity"`
	ExploitMaturity string `json:"exploit_code_maturity"`
	VulnAge         int    `json:"age_of_vuln"`
	ProductCoverage string `json:"product_coverage"` // Availability impact
}

type RiskInfo struct {
	RiskScore          float64  `json:"risk_score"`
	AvailabilityImpact string   `json:"availability_impact"`
	IntegrityImpact    string   `json:"integrity_impact"`
	CVSSV3Base         *float64 `json:"cvss_v3_base"`   // Can be nullable
	CVSSV30Vector      *string  `json:"cvss_v3_vector"` // Can be nullable
}

func adaptDomainPortItem(domainPortItem *domain.PortItem) *PortItem {
	if domainPortItem == nil {
		return nil
	}

	return &PortItem{
		ID:       domainPortItem.ID,
		Protocol: domainPortItem.Protocol,
	}
}

func adaptDomainOSItem(domainOSItem *domain.OSItem) *OSItem {
	if domainOSItem == nil {
		return nil
	}

	return &OSItem{
		Name: domainOSItem.Name,
		Type: domainOSItem.Type,
	}
}

func adaptDomainDateInfo(domainDateInfo domain.DateInfo) DateInfo {
	return DateInfo{
		Published:   domainDateInfo.Published,
		LastUpdated: domainDateInfo.LastUpdated,
	}
}

func adaptDomainPluginInfo(domainPluginInfo domain.PluginInfo) PluginInfo {
	return PluginInfo{
		CPE:      domainPluginInfo.CPE,
		Severity: domainPluginInfo.Severity,
		Version:  domainPluginInfo.Version,
		Type:     domainPluginInfo.Type,
		Family:   domainPluginInfo.Family,
	}
}

func adaptDomainVPRKeyInfo(domainVPRKeyInfo domain.VPRKeyInfo) VPRKeyInfo {
	return VPRKeyInfo{
		ThreatIntensity: domainVPRKeyInfo.ThreatIntensity,
		ExploitMaturity: domainVPRKeyInfo.ExploitMaturity,
		VulnAge:         domainVPRKeyInfo.VulnAge,
		ProductCoverage: domainVPRKeyInfo.ProductCoverage,
	}
}

func adaptDomainRiskInfo(domainRiskInfo domain.RiskInfo) RiskInfo {
	return RiskInfo{
		RiskScore:          domainRiskInfo.RiskScore,
		AvailabilityImpact: domainRiskInfo.AvailabilityImpact,
		IntegrityImpact:    domainRiskInfo.IntegrityImpact,
		CVSSV3Base:         &domainRiskInfo.CVSSV3Base,
		CVSSV30Vector:      &domainRiskInfo.CVSSV30Vector,
	}
}

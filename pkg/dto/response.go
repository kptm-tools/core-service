package dto

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type ServerMessageType string

const (
	MessageInitialDataResponse   ServerMessageType = "initial_data_response"
	MessageVectorUpdateResponse  ServerMessageType = "vector_update_response"
	MessageVectorDetailsResponse ServerMessageType = "vector_details_response"
	MessageReportDataResponse    ServerMessageType = "report_data_response"
)

func (s ServerMessageType) String() string {
	return string(s)
}

type VulnerabilityTypeData struct {
	Name                string    `json:"name"`
	HighestCvss         float64   `json:"highest_cvss"`
	Count               int       `json:"count"`
	Percentage          float64   `json:"percentage"`
	AvailableCvssValues []float64 `json:"available_cvss_values"`
}

// InitialDataResponse (Server -> Client)
type InitialDataResponse struct {
	VulnerabilityTypes         []VulnerabilityTypeData `json:"vulnerability_types"`
	GlobalCVSSScore            float64                 `json:"global_cvss_score"`
	GlobalTotalVulnerabilities int                     `json:"global_total_vulnerabilities"`
}

// ErrorResponse is the payload sent in an error message (Server -> Client)
type ErrorResponse struct {
	Message string `json:"message"`
}

// VectorDetailsResponse (Server -> Client)
type VectorDetailsResponse struct {
	VulnerabilityDetails VulnerabilityDetails `json:"vulnerability_details"`
}

// VulnerabilityDetails represents the details of the vulnerability with the
// highest CVSS for a given vector or vulnerability type selected by the user.
type VulnerabilityDetails struct {
	Name               string  `json:"name"`
	Type               string  `json:"type"`
	CVSS               float64 `json:"cvss"`
	Severity           string  `json:"severity"`
	Description        string  `json:"description"`
	PrivilegesRequired string  `json:"privileges_required"`
	Classification     string  `json:"classification"`
	Integrity          string  `json:"integrity"`
	Availability       string  `json:"availability"`
}

func NewVulnerabilityDetails(vuln domain.Vulnerability) VulnerabilityDetails {
	return VulnerabilityDetails{
		Name:               vuln.VulnerabilityID,
		Type:               vuln.Type,
		CVSS:               vuln.BaseCVSSScore,
		Severity:           vuln.BaseSeverity.String(),
		Description:        vuln.Description,
		PrivilegesRequired: vuln.PrivilegesRequired.String(),
		Classification:     vuln.AccessType.String(),
		Integrity:          vuln.IntegrityImpact.String(),
		Availability:       vuln.AvailabilityImpact.String(),
	}
}

// VectorUpdateResponse (Server -> Client)
type VectorUpdateResponse struct {
	ExpectedGlobalCVSSScore            float64 `json:"expected_global_cvss_score"`
	ExpectedGlobalTotalVulnerabilities int     `json:"expected_global_total_vulnerabilities"`
}

// VectorUpdateMessage is the payload sent in MessageVectorUpdate
type VectorUpdateMessage struct {
	VulnerabilityTypeName string  `json:"vulnerability_type_name"`
	NewValue              float64 `json:"new_value"`
}

// ApplyVectorsMessage is the payload sent in a MessageApplyVectors
type ApplyVectorsMessage struct{}

type ReportDetailsResponse struct {
	SolvedVulnerabilities     []ScanVulnerabilityItem `json:"solved_vulnerabilities"`
	UnattendedVulnerabilities []ScanVulnerabilityItem `json:"unattended_vulnerabilities"`
	ExpectedSecurityPosture   float64                 `json:"expected_security_posture"`
	GraphData                 GraphData               `json:"vulnerability_graph"`
}

type GraphData struct {
	Series []Series `json:"series"` // Represents each different line in the chart that must be plotted
}

type Series struct {
	Name    string      `json:"name"`
	Data    []DataPoint `json:"data"`
	Average float64     `json:"average,omitempty"` // Optional field for static value (e.g: average)
}

type DataPoint struct {
	X string  `json:"x"`
	Y float64 `json:"y"`
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
	ID             int                   `json:"id"`
	Name           string                `json:"name"`
	Type           string                `json:"type"`
	Severity       string                `json:"severity"`
	MaxCVSS        float64               `json:"max_cvss"`
	RiskScore      float64               `json:"risk_score"`
	ImpactScore    float64               `json:"impact_score"`
	Likelihood     string                `json:"likelihood"`
	Access         string                `json:"access"`
	Complexity     string                `json:"complexity"`
	Privileges     string                `json:"privileges"`
	Exploitability string                `json:"exploitability"`
	Description    string                `json:"description"`
	Comment        string                `json:"comment"`
	VendorComments []tools.VendorComment `json:"vendor_comments"`
	References     []string              `json:"references"`
}

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
	VulnerabilityCount *int   `json:"vulnerability_count"`
}

type UserPermissionsResponse struct {
	UserRoles                       []domain.Role   `json:"user_roles"`
	DeniedActions                   []domain.Action `json:"denied_actions"`
	EffectivePermissionsLastUpdated time.Time       `json:"effective_permissions_last_updated"`
}

func AdaptCategoryData(serviceCategoryData []domain.ServiceCategoryData) []CategoryData {
	adaptedData := make([]CategoryData, len(serviceCategoryData))
	for i, svcData := range serviceCategoryData {
		adaptedData[i] = CategoryData{
			Category: svcData.Category,
			Count:    svcData.Count,
		}
	}
	return adaptedData
}

func AdaptTimePeriods(serviceTimePeriodData []domain.ServiceTimePeriod) []TimePeriod {
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

	Description    string                `json:"description"`
	Comment        string                `json:"comment"`
	VendorComments []tools.VendorComment `json:"vendor_comments"`
	References     []string              `json:"references"`

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

func AdaptDomainPortItem(domainPortItem *domain.PortItem) *PortItem {
	if domainPortItem == nil {
		return nil
	}

	return &PortItem{
		ID:       domainPortItem.ID,
		Protocol: domainPortItem.Protocol,
	}
}

func AdaptDomainOSItem(domainOSItem *domain.OSItem) *OSItem {
	if domainOSItem == nil {
		return nil
	}

	return &OSItem{
		Name: domainOSItem.Name,
		Type: domainOSItem.Type,
	}
}

func AdaptDomainDateInfo(domainDateInfo domain.DateInfo) DateInfo {
	return DateInfo{
		Published:   domainDateInfo.Published,
		LastUpdated: domainDateInfo.LastUpdated,
	}
}

func AdaptDomainPluginInfo(domainPluginInfo domain.PluginInfo) PluginInfo {
	return PluginInfo{
		CPE:      domainPluginInfo.CPE,
		Severity: domainPluginInfo.Severity,
		Version:  domainPluginInfo.Version,
		Type:     domainPluginInfo.Type,
		Family:   domainPluginInfo.Family,
	}
}

func AdaptDomainVPRKeyInfo(domainVPRKeyInfo domain.VPRKeyInfo) VPRKeyInfo {
	return VPRKeyInfo{
		ThreatIntensity: domainVPRKeyInfo.ThreatIntensity,
		ExploitMaturity: domainVPRKeyInfo.ExploitMaturity,
		VulnAge:         domainVPRKeyInfo.VulnAge,
		ProductCoverage: domainVPRKeyInfo.ProductCoverage,
	}
}

func AdaptDomainRiskInfo(domainRiskInfo domain.RiskInfo) RiskInfo {
	return RiskInfo{
		RiskScore:          domainRiskInfo.RiskScore,
		AvailabilityImpact: domainRiskInfo.AvailabilityImpact,
		IntegrityImpact:    domainRiskInfo.IntegrityImpact,
		CVSSV3Base:         &domainRiskInfo.CVSSV3Base,
		CVSSV30Vector:      &domainRiskInfo.CVSSV30Vector,
	}
}

func ToScanVulnerabilityItem(vuln *domain.Vulnerability) ScanVulnerabilityItem {
	var analystComment string
	if vuln.AnalystComment == nil {
		analystComment = ""
	} else {
		analystComment = *vuln.AnalystComment
	}

	return ScanVulnerabilityItem{
		ID:             vuln.ID,
		Name:           vuln.VulnerabilityID,
		Type:           vuln.Type,
		Severity:       vuln.BaseSeverity.String(),
		MaxCVSS:        vuln.BaseCVSSScore,
		RiskScore:      vuln.RiskScore,
		ImpactScore:    vuln.ImpactScore,
		Likelihood:     vuln.Likelihood.String(),
		Access:         vuln.AccessType.String(),
		Complexity:     vuln.Complexity.String(),
		Privileges:     vuln.PrivilegesRequired.String(),
		Exploitability: vuln.Exploit.Exploitability.String(),
		Description:    vuln.Description,
		Comment:        analystComment,
		VendorComments: vuln.VendorComments,
		References:     vuln.References,
	}
}

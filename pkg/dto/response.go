package dto

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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

func NewVulnerabilityDetails(vuln tools.Vulnerability) VulnerabilityDetails {
	return VulnerabilityDetails{
		Name:               vuln.CveID,
		Type:               vuln.Type.String(),
		CVSS:               vuln.BaseCVSSScore,
		Severity:           vuln.BaseSeverity.String(),
		Description:        vuln.Description,
		PrivilegesRequired: vuln.PrivilegesRequired.String(),
		Classification:     vuln.Access.String(),
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

// ScanAssetsOperatingSystem store system data detected on a host.
// @name ScanAssetsOperatingSystem
type ScanAssetsOperatingSystem struct {
	// id is the unique identifier for the OS record.
	// required: true
	ID int32 `json:"id"`

	// host_id is the identifier of the scanned host.
	// required: true
	HostID string `json:"host_id"`

	// scan_id is the identifier of the scan this record belongs to.
	// required: true
	ScanID string `json:"scan_id"`

	// Fullname of the operating system with user (e.g. "Ubuntu").
	// required: true
	FullName string `json:"full_name"`

	// name of the operating system (e.g. "Ubuntu").
	// required: true
	Name string `json:"name"`

	// version of the operating system (e.g. "20.04").
	Version string `json:"version"`

	// family groups this OS into a family (e.g. "Linux").
	Family string `json:"family"`

	// os_type indicates the OS type (e.g. "unix", "windows").
	OSType string `json:"os_type"`

	// fingerprint used to identify the OS.
	// Fingerprint string `json:"fingerprint"`

	// cpe is the Common Platform Enumeration string.
	CPE string `json:"cpe"`

	// accuracy is the confidence percentage of the detection.
	Accuracy int `json:"accuracy"`

	// total_vulnerabilities_count total number of detected vulnerabilities.
	TotalVulnerabilities int `json:"total_vulnerabilities_count"`

	// critical_count count of critical vulnerabilities.
	CriticalCount int `json:"critical_count"`

	// high_count count of high-severity vulnerabilities.
	HighCount int `json:"high_count"`

	// medium_count count of medium-severity vulnerabilities.
	MediumCount int `json:"medium_count"`

	// low_count count of low-severity vulnerabilities.
	LowCount int `json:"low_count"`

	// none_count count of items without severity classification.
	NoneCount int `json:"none_count"`

	// unknown_count count of vulnerabilities with unknown severity.
	UnknownCount int `json:"unknown_count"`
}

// ScanAssetsService store service data detected on a host.
// @name ScanAssetsService
type ScanAssetsService struct {
	// id is the unique identifier for the service record.
	// required: true
	ID int32 `json:"id"`

	// host_id is the identifier of the scanned host.
	// required: true
	HostID string `json:"host_id"`

	// scan_id is the identifier of the scan this record belongs to.
	// required: true
	ScanID string `json:"scan_id"`

	// name of the service (e.g. "ssh").
	Name string `json:"name"`

	// version of the service or product.
	Version string `json:"version"`

	// port number where the service is running.
	Port int `json:"port"`

	// protocol used by the service (e.g. "tcp", "udp").
	Protocol string `json:"protocol"`

	// cpe is the Common Platform Enumeration string.
	CPE string `json:"cpe"`

	// product name (e.g. "OpenSSH").
	Product string `json:"product"`

	// port_state indicates the port state (e.g. "open", "closed").
	PortState string `json:"port_state"`

	// total_vulnerabilities_count total number of detected vulnerabilities.
	TotalVulnerabilities int `json:"total_vulnerabilities_count"`

	// critical_count count of critical vulnerabilities.
	CriticalCount int `json:"critical_count"`

	// high_count count of high-severity vulnerabilities.
	HighCount int `json:"high_count"`

	// medium_count count of medium-severity vulnerabilities.
	MediumCount int `json:"medium_count"`

	// low_count count of low-severity vulnerabilities.
	LowCount int `json:"low_count"`

	// none_count count of items without severity classification.
	NoneCount int `json:"none_count"`

	// unknown_count count of vulnerabilities with unknown severity.
	UnknownCount int `json:"unknown_count"`
}

// ScanAssetsResponse Contains operating system and service asset information for a scan.
// @name ScanAssetsResponse
type ScanAssetsResponse struct {
	// operating_system holds the data of the detected operating system.
	// required: true
	OperatingSystem ScanAssetsOperatingSystem `json:"operating_system"`

	// services is the list of services detected on the host.
	// required: true
	Services []ScanAssetsService `json:"services"`
}

// ScanVulnerabilityItemsResponse is the DTO for the list of Vulnerabilities
// associated to a scan.
type ScanVulnerabilityItemsResponse struct {
	ScanDate             time.Time               `json:"scan_date"`
	Alias                string                  `json:"alias"`
	TotalVulnerabilities int                     `json:"total_vulnerabilities"`
	SeverityCounts       tools.SeverityCounts    `json:"severity_counts"`
	Vulnerabilities      []ScanVulnerabilityItem `json:"vulnerabilities"`
}

type ScanVulnerabilityDetectedOSResponse struct {
	ScanID               string                  `json:"scan_id"`
	ScanDate             time.Time               `json:"scan_date"`
	Alias                string                  `json:"alias"`
	IPAddress            string                  `json:"ip_address"`
	OSName               string                  `json:"os_name"`
	OSType               string                  `json:"os_type"`
	TotalVulnerabilities int                     `json:"total_vulnerabilities"`
	SeverityCounts       tools.SeverityCounts    `json:"severity_counts"`
	Vulnerabilities      []ScanVulnerabilityItem `json:"vulnerabilities"`
	References           []string                `json:"references"`
}

type WebVulnerabilitySummary struct {
	VulnerabilityID string                            `json:"vulnerability_id"`
	ScanID          string                            `json:"scan_id"`
	HostID          string                            `json:"host_id"`
	ServiceID       string                            `json:"service_id"`
	Title           string                            `json:"title"`
	Severity        string                            `json:"severity"`
	InstancesCount  int                               `json:"instances_count"`
	CWERemediations []domain.CWEDetailWithMitigations `json:"remediations"`
}

type ScanVulnerabilityDetectedServiceResponse struct {
	ScanID               string                    `json:"scan_id"`
	ScanDate             time.Time                 `json:"scan_date"`
	ServiceName          string                    `json:"service_name"`
	ServiceVersion       string                    `json:"service_version"`
	ServiceConfidence    int32                     `json:"service_confidence"`
	ServiceCPE           string                    `json:"service_cpe"`
	ServiceProduct       string                    `json:"service_product"`
	ServiceProtocol      string                    `json:"service_protocol"`
	ServicePort          int                       `json:"service_port"`
	ServicePortState     string                    `json:"service_port_state"`
	TotalVulnerabilities int                       `json:"total_vulnerabilities"`
	SeverityCounts       tools.SeverityCounts      `json:"severity_counts"`
	Vulnerabilities      []ScanVulnerabilityItem   `json:"vulnerabilities"`
	References           []string                  `json:"references"`
	WebVulnerabilities   []WebVulnerabilitySummary `json:"web_vulnerabilities"`
}

type ScanVulnerabilityItem struct {
	ID              uuid.UUID             `json:"id"`
	Name            string                `json:"name"`
	Type            string                `json:"type"`
	Severity        string                `json:"severity"`
	MaxCVSS         float64               `json:"max_cvss"`
	RiskScore       float64               `json:"risk_score"`
	ImpactScore     float64               `json:"impact_score"`
	Likelihood      string                `json:"likelihood"`
	Access          string                `json:"access"`
	Complexity      string                `json:"complexity"`
	Privileges      string                `json:"privileges"`
	Exploitability  string                `json:"exploitability"`
	Description     string                `json:"description"`
	Comment         string                `json:"comment"`
	VendorComments  []tools.VendorComment `json:"vendor_comments"`
	References      []string              `json:"references"`
	CWERemediations []CWERemediation      `json:"remediations"`
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
// scan's vulnerability.
type ScanVulnerabilityDetailResponse struct {
	ID       string `json:"id"`
	ScanDate string `json:"scan_date"`

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

	Metrics []CVSSMetric `json:"metrics"`

	CWERemediations []CWERemediation `json:"remediations"`

	EPSSScore      *float64   `json:"epss_score,omitempty"`
	EPSSPercentile *float64   `json:"epss_percentile,omitempty"`
	EPSSDate       *time.Time `json:"epss_date,omitempty"`

	DateInfo   DateInfo   `json:"date"`
	PluginInfo PluginInfo `json:"plugin"`
	VPRKeyD    VPRKeyInfo `json:"vpr_key_d"`
	RiskInfo   RiskInfo   `json:"risk"`
}

type CVSSMetric struct {
	Version             string   `json:"version"`
	BaseScore           *float64 `json:"base_score"`
	ImpactScore         *float64 `json:"impact_score"`
	Severity            *string  `json:"severity"`
	Access              *string  `json:"access"`
	Complexity          *string  `json:"complexity"`
	PrivilegesRequired  *string  `json:"privileges_required"`
	IntegrityImpact     *string  `json:"integrity_impact"`
	AvailabilityImpact  *string  `json:"availability_impact"`
	ExploitabilityScore *float64 `json:"exploitability_score"`
	Exploitability      *string  `json:"exploitability"`
}

type CWERemediation struct {
	ID                 string    `json:"cwe_id"`
	MitigationID       *string   `json:"mitigation_id"`
	Title              string    `json:"title"`
	Phase              *string   `json:"phase"`
	Description        string    `json:"description"`
	Effectiveness      *string   `json:"effectiveness"`
	EffectivenessNotes *string   `json:"effectiveness_notes"`
	LastUpdated        time.Time `json:"last_updated"`
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
	Published   string `json:"published"`
	LastUpdated string `json:"last_updated"`
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

type HostResponse struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Domain      string              `json:"domain"`
	IP          string              `json:"ip"`
	Credentials []domain.Credential `json:"credentials"`
	Rapporteurs []domain.Rapporteur `json:"rapporteurs"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// ScanWebVulnerabilityResponse is the DTO for a Web Vulnerability
// associated to a scan.
type ScanWebVulnerabilityResponse struct {
	VulnID          string                            `json:"vulnerability_id"`
	ScanID          string                            `json:"scan_id"`
	HostID          string                            `json:"host_id"`
	SolutionAdvice  string                            `json:"solution_advice"`
	ServiceID       string                            `json:"service_id"`
	CreatedAt       *time.Time                        `json:"created_at"`
	UpdatedAt       *time.Time                        `json:"updated_at"`
	Instances       []domain.WebVulnerabilityInstance `json:"instances"`
	Reference       string                            `json:"reference"`
	CweID           string                            `json:"cwe_id"`
	WascID          string                            `json:"wasc_id"`
	CWERemediations []domain.CWEDetailWithMitigations `json:"remediations"`
}

func NewHostResponse(host domain.Host) HostResponse {
	return HostResponse{
		ID:          host.ID.String(),
		Name:        host.Name,
		Domain:      host.Domain,
		IP:          host.IP,
		Credentials: host.Credentials,
		Rapporteurs: host.Rapporteurs,
		CreatedAt:   host.CreatedAt,
		UpdatedAt:   host.UpdatedAt,
	}
}

func AdaptDomainPortItem(domainPortItem *domain.PortItem) *PortItem {
	if domainPortItem == nil {
		return nil
	}

	return &PortItem{
		ID:       uint16(domainPortItem.ID),
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
		Published:   domainDateInfo.Published.Format(time.DateOnly),
		LastUpdated: domainDateInfo.LastUpdated.Format(time.DateOnly),
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

func ToScanVulnerabilityItem(vuln tools.Vulnerability) ScanVulnerabilityItem {
	return ScanVulnerabilityItem{
		ID:             vuln.ID,
		Name:           vuln.CveID,
		Description:    vuln.Description,
		Type:           vuln.Type.String(),
		Severity:       vuln.BaseSeverity.String(),
		MaxCVSS:        vuln.BaseCVSSScore,
		RiskScore:      vuln.RiskScore,
		ImpactScore:    vuln.ImpactScore,
		Likelihood:     vuln.Likelihood.String(),
		Access:         vuln.Access.String(),
		Complexity:     vuln.Complexity.String(),
		Privileges:     vuln.PrivilegesRequired.String(),
		Exploitability: vuln.Exploit.Exploitability.String(),
		Comment:        vuln.AnalystComment,
		VendorComments: vuln.VendorComments,
		References:     vuln.References,
	}
}

func ToCVSSMetrics(cvssMetrics []tools.CVSSMetric) []CVSSMetric {
	if len(cvssMetrics) == 0 {
		return []CVSSMetric{}
	}

	result := make([]CVSSMetric, 0, len(cvssMetrics))
	for _, cm := range cvssMetrics {
		// convert enum types to strings and get pointers
		severityStr := cm.Severity.String()
		accessStr := cm.Access.String()
		complexityStr := cm.Complexity.String()
		privRequiredStr := cm.PrivilegesRequired.String()
		integrityStr := cm.IntegrityImpact.String()
		availabilityStr := cm.AvailabilityImpact.String()
		exploitStr := cm.Exploitability.String()

		m := CVSSMetric{
			Version:             string(cm.Version),
			BaseScore:           &cm.BaseScore,
			ImpactScore:         &cm.ImpactScore,
			Severity:            &severityStr,
			Access:              &accessStr,
			Complexity:          &complexityStr,
			PrivilegesRequired:  &privRequiredStr,
			IntegrityImpact:     &integrityStr,
			AvailabilityImpact:  &availabilityStr,
			ExploitabilityScore: &cm.ExploitabilityScore,
			Exploitability:      &exploitStr,
		}
		result = append(result, m)
	}
	return result
}

func ToCWERemediation(cweRemediations []tools.CWERemediation) []CWERemediation {
	if len(cweRemediations) == 0 {
		return []CWERemediation{}
	}

	result := make([]CWERemediation, 0, len(cweRemediations))
	for _, cwe := range cweRemediations {
		// Defensive check for Phase slice with zero elements before accessing Phase[0]
		var phasePtr *string
		if len(cwe.Phase) > 0 {
			phasePtr = &cwe.Phase[0]
		} else {
			phasePtr = nil
		}

		r := CWERemediation{
			ID:                 cwe.ID,
			MitigationID:       &cwe.MitigationID,
			Title:              cwe.Title,
			Phase:              phasePtr,
			Description:        cwe.Description,
			Effectiveness:      &cwe.Effectiveness,
			EffectivenessNotes: &cwe.EffectivenessNotes,
			LastUpdated:        cwe.LastUpdated,
		}
		result = append(result, r)
	}
	return result
}

// ConvertScanOSandServicesResultToResponse takes a slice of ScanOSandServicesResult,
// separates and converts them into a structured ScanAssetsResponse.
func ConvertScanOSandServicesResultToResponse(results []domain.ScanOSandServicesResult) ScanAssetsResponse {
	var response ScanAssetsResponse

	for _, r := range results {
		switch r.AssetType {
		case "os":
			cpeSplit := strings.Split(r.Cpe, ":")
			version := cpeSplit[len(cpeSplit)-1]

			// Map OS
			response.OperatingSystem = ScanAssetsOperatingSystem{
				ID:       r.ID,
				HostID:   r.HostID.String(),
				ScanID:   r.ScanID.String(),
				FullName: r.Name,
				Name:     r.Name,
				Version:  version,
				Family:   r.Family,
				OSType:   r.OsType,
				// Fingerprint:          r.Fingerprint,
				CPE:                  r.Cpe,
				Accuracy:             int(r.Accuracy),
				TotalVulnerabilities: int(r.TotalVulnerabilitiesCount),
				CriticalCount:        int(r.CriticalCount),
				HighCount:            int(r.HighCount),
				MediumCount:          int(r.MediumCount),
				LowCount:             int(r.LowCount),
				NoneCount:            int(r.NoneCount),
				UnknownCount:         int(r.UnknownCount),
			}
		case "service":
			service := ScanAssetsService{
				ID:                   r.ID,
				HostID:               r.HostID.String(),
				ScanID:               r.ScanID.String(),
				Name:                 r.Name,
				Version:              r.Version,
				Port:                 int(r.Port),
				Protocol:             r.Protocol,
				CPE:                  r.Cpe,
				Product:              r.Product,
				PortState:            r.PortState,
				TotalVulnerabilities: int(r.TotalVulnerabilitiesCount),
				CriticalCount:        int(r.CriticalCount),
				HighCount:            int(r.HighCount),
				MediumCount:          int(r.MediumCount),
				LowCount:             int(r.LowCount),
				NoneCount:            int(r.NoneCount),
				UnknownCount:         int(r.UnknownCount),
			}
			response.Services = append(response.Services, service)
		}
	}

	return response
}

func ConvertDomWebVulnToDtoWebVuln(vulnerability domain.WebVulnerability) ScanWebVulnerabilityResponse {
	return ScanWebVulnerabilityResponse{
		VulnID:          vulnerability.VulnerabilityID.String(),
		ScanID:          vulnerability.ScanID.String(),
		HostID:          vulnerability.HostID.String(),
		SolutionAdvice:  vulnerability.SolutionAdvice,
		ServiceID:       strconv.Itoa(int(vulnerability.ServiceID)),
		CreatedAt:       vulnerability.CreatedAt,
		UpdatedAt:       vulnerability.UpdatedAt,
		Instances:       vulnerability.Instances,
		Reference:       vulnerability.Reference,
		CweID:           vulnerability.CweID,
		WascID:          vulnerability.WascID,
		CWERemediations: vulnerability.CWERemediations,
	}
}

func ConvertToWebVulnSummaryToResponse(results []domain.WebVulnerability) []WebVulnerabilitySummary {
	summaries := make([]WebVulnerabilitySummary, len(results))
	for i, r := range results {
		summaries[i] = WebVulnerabilitySummary{
			VulnerabilityID: r.VulnerabilityID.String(),
			ScanID:          r.ScanID.String(),
			HostID:          r.HostID.String(),
			ServiceID:       strconv.Itoa(int(r.ServiceID)),
			Title:           r.Title,
			Severity:        r.Severity,
			InstancesCount:  len(r.Instances),
			CWERemediations: r.CWERemediations,
		}
	}
	return summaries
}

package dto

import (
	"time"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type ClientMessageType string

const (
	MessageInitialRequest ClientMessageType = "initial_data_request"
	MessageVectorUpdate   ClientMessageType = "vector_update"
	MessageSelectVector   ClientMessageType = "select_vector"
	MessageApplyVectors   ClientMessageType = "apply_vectors_request"
)

func (s ClientMessageType) String() string {
	return string(s)
}

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

// InitialDataRequest is the payload send in a MessageInitialRequest (Client -> Server)
type InitialDataRequest struct {
	ScanID string `json:"scan_id"`
}

type VulnerabilityTypeData struct {
	Name                string    `json:"name"`
	HighestCvss         float64   `json:"highest_cvss"`
	Count               int       `json:"count"`
	Percentage          float64   `json:"percentage"`
	AvailableCvssValues []float64 `json:"available_cvss_values"`
}

// InitialDataReponse (Server -> Client)
type InitialDataReponse struct {
	VulnerabilityTypes         []VulnerabilityTypeData `json:"vulnerability_types"`
	GlobalCVSSScore            float64                 `json:"global_cvss_score"`
	GlobalTotalVulnerabilities int                     `json:"global_total_vulnerabilities"`
}

// ErrorResponse is the payload sent in an error message (Server -> Client)
type ErrorResponse struct {
	Message string `json:"message"`
}

// SelectVectorRequest is the payload sent in a MessageSelectVector (Client -> Server)
type SelectVectorRequest struct {
	VulnerabilityTypeName string `json:"vulnerability_type_name"`
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

// VectorUpdateReponse (Server -> Client)
type VectorUpdateReponse struct {
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

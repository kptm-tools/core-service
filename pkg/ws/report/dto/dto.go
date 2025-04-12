package dto

import (
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
	SolvedVulnerabilities     []*domain.Vulnerability `json:"solved_vulnerabilities"`
	UnattendedVulnerabilities []*domain.Vulnerability `json:"unattended_vulnerabilities"`
	ExpectedSecurityPosture   float64                 `json:"expected_security_posture"`
}

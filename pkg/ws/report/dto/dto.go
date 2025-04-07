package dto

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

package services

import (
	"github.com/kptm-tools/common/common/pkg/results/tools"
)

// GeneratePortDataFromWebVuln creates PortData based on WebVulnerability information
func GeneratePortDataFromWebVuln(vuln tools.WebVulnerability) tools.PortData {
	portData := tools.PortData{
		ID:       80,
		Protocol: "tcp",
		Service: tools.Service{
			Name: "http",
		},
		State:           "open",
		Vulnerabilities: nil,
	}
	if vuln.WascID == "45" {
		portData.ID = 443
		portData.Protocol = "tcp"
		portData.Service.Name = "nginx"
	}
	return portData
}

// Removed GenerateCWEDetailFromVuln and related functions as they are no longer needed.
// CWE data is now pre-populated in the database and only stub records are created for unknown CWEs.

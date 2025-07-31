package services

import (
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"time"
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

// GenerateCWEDetailFromVuln creates CWEDetail from tools.Vulnerability
func GenerateCWEDetailFromVuln(vuln tools.Vulnerability) domain.CWEDetail {
	// Extract CWE ID from first CWERemediation record
	var cweID string
	if len(vuln.CWERemediation) > 0 {
		cweID = vuln.CWERemediation[0].ID
	}

	// Extract title from first CWERemediation record
	title := ExtractCWETitleFromRemediation(vuln.CWERemediation)
	lastUpdate := ExtractCWELastUpdatedAtFromRemediation(vuln.CWERemediation)
	now := time.Now()
	return domain.CWEDetail{
		ID:          cweID,
		Title:       title,
		CreatedAt:   &now,
		LastUpdated: lastUpdate,
	}
}

// GenerateCWEDetailFromWebVuln creates CWEDetail from tools.WebVulnerability
func GenerateCWEDetailFromWebVuln(vuln tools.WebVulnerability) domain.CWEDetail {
	now := time.Now()
	return domain.CWEDetail{
		ID:          vuln.CweID,
		CreatedAt:   &now,
		LastUpdated: &now,
	}
}

// ExtractCWETitleFromRemediation extracts title from CWE remediation data
func ExtractCWETitleFromRemediation(remediations []tools.CWERemediation) string {
	if len(remediations) > 0 {
		return remediations[0].Title
	}
	return ""
}

// ExtractCWELastUpdatedAtFromRemediation extracts title from CWE remediation data
func ExtractCWELastUpdatedAtFromRemediation(remediations []tools.CWERemediation) *time.Time {
	if len(remediations) > 0 {
		return &remediations[0].LastUpdated
	}
	return nil
}

package utils

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func GetScanID(req *http.Request) (uuid.UUID, error) {
	reqUUID := req.PathValue("scanId")

	u, err := uuid.Parse(reqUUID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse uuid: %w", err)
	}
	return u, nil
}

func GetTenantIDFromQuery(req *http.Request) (string, error) {
	tenantID := req.URL.Query().Get("tenantId")

	if tenantID == "" {
		return "", fmt.Errorf("tenantId missing in query params")
	}

	return tenantID, nil
}

func GetOTPFromQuery(req *http.Request) (string, error) {
	otpKey := req.URL.Query().Get("otp")

	if otpKey == "" {
		return "", fmt.Errorf("otp missing in query params")
	}

	return otpKey, nil
}

func GetMaxCVSSPerType(vulns []*domain.Vulnerability) map[enums.WeaknessType]float64 {
	weaknessMap := make(map[enums.WeaknessType]float64)

	// Initialize the map with all possible WeaknessType enums and default values
	for i := enums.WeaknessSSRF; i <= enums.WeaknessNoInfo; i++ {
		weaknessMap[i] = 0.0
	}

	// Iterate through vulnerabilities and update the map with maximum CVSS values
	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		wt, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type", slog.String("vuln_type", vuln.Type))
			continue
		}

		currentCVSS := vuln.BaseCVSSScore
		if maxCVSS, exists := weaknessMap[wt]; exists {
			if currentCVSS > maxCVSS {
				weaknessMap[wt] = currentCVSS
			}
		} else {
			weaknessMap[wt] = currentCVSS
		}
	}

	return weaknessMap
}

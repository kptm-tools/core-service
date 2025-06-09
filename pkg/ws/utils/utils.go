package utils

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

func GetScanID(req *http.Request) (uuid.UUID, error) {
	reqUUID := req.PathValue("scanId")

	u, err := uuid.Parse(reqUUID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse uuid: %w", err)
	}
	return u, nil
}

func GetTenantIDFromQuery(req *http.Request) (uuid.UUID, error) {
	reqTenantID := req.URL.Query().Get("tenantId")

	if reqTenantID == "" {
		return uuid.Nil, fmt.Errorf("tenantId missing in query params")
	}

	u, err := uuid.Parse(reqTenantID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse uuid: %w", err)
	}

	return u, nil
}

func GetOTPFromQuery(req *http.Request) (string, error) {
	otpKey := req.URL.Query().Get("otp")

	if otpKey == "" {
		return "", fmt.Errorf("otp missing in query params")
	}

	return otpKey, nil
}

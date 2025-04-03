package utils

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

func GetTenantIDFromHeader(req *http.Request) (string, error) {
	tenantID := req.Header.Get("X-TenantId")

	if err := uuid.Validate(tenantID); err != nil {
		return "", fmt.Errorf("invalid UUID: `%s`", tenantID)
	}
	return tenantID, nil
}

func GetScanID(req *http.Request) (uuid.UUID, error) {
	reqUUID := req.PathValue("scanId")

	u, err := uuid.Parse(reqUUID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse uuid: %w", err)
	}
	return u, nil
}

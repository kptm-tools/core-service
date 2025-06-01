package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/cockroachdb/apd/v3"
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/sqlc-dev/pqtype"
)

// nullStringToString converts sql.NullString to string, returning "" if null.
func nullStringToString(ns sql.NullString) string {
	return ns.String
}

// nullTimeToTime converts sql.NullTime to time.Time, returning time.Time{} if null.
func nullTimeToTime(nt sql.NullTime) time.Time {
	return nt.Time
}

// nullUUIDToUUID converts uuid.NullUUID to uuid.UUID, returning uuid.Nil if null.
func nullUUIDToUUID(nu uuid.NullUUID) uuid.UUID {
	return nu.UUID
}

// nullDecimalToFloat64 converts apd.NullDecimal to float64.
// It returns 0.0 and an error if conversion fails or if the decimal is null.
// Note: This matches your example's error handling for this specific conversion.
func nullDecimalToFloat64(nd apd.NullDecimal) (float64, error) {
	if !nd.Valid {
		return 0.0, nil // Or return an error if you strictly want to differentiate null from zero
	}
	f, err := nd.Decimal.Float64()
	if err != nil {
		return 0.0, fmt.Errorf("failed to convert decimal to float64: %w", err)
	}
	return f, nil
}

// parseNullStringAsFloat64 attempts to parse a sql.NullString into a float64.
// Returns 0.0 and an error if the string is null or cannot be parsed.
func parseNullStringAsFloat64(ns sql.NullString) (float64, error) {
	if !ns.Valid || ns.String == "" {
		return 0.0, nil // Return zero if not valid or empty, no error
	}
	f, err := strconv.ParseFloat(ns.String, 64)
	if err != nil {
		return 0.0, fmt.Errorf("failed to parse string '%s' to float64: %w", ns.String, err)
	}
	return f, nil
}

func unmarshalNvdReferences(nvdRaw pqtype.NullRawMessage) ([]string, error) {
	if !nvdRaw.Valid {
		return []string{}, nil
	}

	if len(nvdRaw.RawMessage) == 0 || string(nvdRaw.RawMessage) == "null" {
		return []string{}, nil
	}

	var refs []string
	err := json.Unmarshal(nvdRaw.RawMessage, &refs)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NvdReferences JSON: %w", err)
	}
	return refs, nil
}

func unmarshalNvdVendorComments(nvdRaw pqtype.NullRawMessage) ([]tools.VendorComment, error) {
	if !nvdRaw.Valid {
		return []tools.VendorComment{}, nil
	}

	if len(nvdRaw.RawMessage) == 0 || string(nvdRaw.RawMessage) == "null" {
		return []tools.VendorComment{}, nil
	}
	var vendorComments []tools.VendorComment
	err := json.Unmarshal(nvdRaw.RawMessage, &vendorComments)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NvdVendorComments: %w", err)
	}
	return vendorComments, nil
}

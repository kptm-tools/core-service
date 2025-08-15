package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/kptm-tools/common/common/pkg/enums"
	"strconv"
	"time"

	"github.com/cockroachdb/apd/v3"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/sqlc-dev/pqtype"
)

// floatToAPDNullDecimal converts float64 to apd.NullDecimal using a specified format string.
// Assumes that if the source float64 is present, it's a valid value to store.
// If 0.0 from source should mean SQL NULL, your tools.Vulnerability should use *float64.
func floatToAPDNullDecimal(f float64, formatSpecifier string) (apd.NullDecimal, error) {
	s := fmt.Sprintf(formatSpecifier, f)
	decVal, _, err := apd.NewFromString(s)
	if err != nil {
		return apd.NullDecimal{}, fmt.Errorf("string_to_apd_decimal: failed to create decimal from string '%s' (source float: %f): %w", s, f, err)
	}
	return apd.NullDecimal{Decimal: *decVal, Valid: true}, nil
}

// floatToSQLNullString converts float64 to sql.NullString using a specified format string.
// Used for CVSS v2/v3.0 scores and EPSS scores as per your CreateCVEDetailParams.
// considerZeroAsNull: if true and f is 0.0, returns SQL NULL.
func floatToSQLNullString(f float64, formatSpecifier string, considerZeroAsNull bool) sql.NullString {
	if considerZeroAsNull && f == 0.0 {
		return sql.NullString{Valid: false}
	}
	s := fmt.Sprintf(formatSpecifier, f)
	return sql.NullString{String: s, Valid: true}
}

// stringToSQLNullString converts a Go string to sql.NullString.
// Empty string becomes SQL NULL.
func stringToSQLNullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// enumToSQLNullString converts a Go enum (that has a .String() method) to sql.NullString.
// If the enum's string representation is empty or matches a "zero/unknown" value, it becomes SQL NULL.
func enumToSQLNullString[E interface{ String() string }](val E, isZeroValue func(E) bool) sql.NullString {
	if isZeroValue(val) {
		return sql.NullString{Valid: false}
	}
	sVal := val.String()
	if sVal == "" { // Double check, as some enums might stringify their zero value to non-empty
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: sVal, Valid: true}
}

// marshalToPQNullRawMessage converts an interface to pqtype.NullRawMessage for JSONB.
func marshalToPQNullRawMessage(data interface{}) (pqtype.NullRawMessage, error) {
	if data == nil {
		return pqtype.NullRawMessage{Valid: false}, nil
	}

	bytes, err := json.Marshal(data)
	if err != nil {
		return pqtype.NullRawMessage{}, fmt.Errorf("marshal_to_jsonb: failed to marshal data: %w", err)
	}

	// If marshalled result is "null" (e.g. from a nil pointer that was not caught by data == nil), treat as NULL.
	// Or if it's an empty JSON array/object and you want that as NULL. For now, "null" is key.
	if string(bytes) == "null" {
		return pqtype.NullRawMessage{Valid: false}, nil
	}
	return pqtype.NullRawMessage{RawMessage: bytes, Valid: true}, nil
}

// nullStringToString converts sql.NullString to string, returning "" if null.
func nullStringToString(ns sql.NullString) string {
	return ns.String
}

// nullTimeToTime converts sql.NullTime to time.Time, returning time.Time{} if null.
func nullTimeToTime(nt sql.NullTime) time.Time {
	return nt.Time
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

func unmarshalToolResult(toolResultRawMessage pqtype.NullRawMessage, toolName enums.ToolName) (*tools.ToolResult, error) {
	toolResult := tools.ToolResult{
		Tool: toolName,
	}
	if !toolResultRawMessage.Valid {
		return &toolResult, nil
	}
	if len(toolResultRawMessage.RawMessage) == 0 || string(toolResultRawMessage.RawMessage) == "null" {
		return &toolResult, nil
	}

	var result tools.IToolResult
	switch toolName {
	case enums.ToolWhoIs:
		var whois tools.WhoIsResult
		if err := json.Unmarshal(toolResultRawMessage.RawMessage, &whois); err != nil {
			return nil, fmt.Errorf("failed to unmarshal WhoIsResult: %w", err)
		}
		result = &whois
	case enums.ToolHarvester:
		var harvester tools.HarvesterResult
		if err := json.Unmarshal(toolResultRawMessage.RawMessage, &harvester); err != nil {
			return nil, fmt.Errorf("failed to unmarshal HarvesterResult: %w", err)
		}
		result = &harvester
	case enums.ToolDNSLookup:
		var dns tools.DNSLookupResult
		if err := json.Unmarshal(toolResultRawMessage.RawMessage, &dns); err != nil {
			return nil, fmt.Errorf("failed to unmarshal DNSLookupResult: %w", err)
		}
		result = &dns
	default:
		return nil, fmt.Errorf("unsupported tool name: %v", toolName)
	}

	toolResult.Result = result
	return &toolResult, nil
}

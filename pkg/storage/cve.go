package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type CVERepo struct {
	defaultQueries *repository.Queries
}

var _ interfaces.CVERepository = (*CVERepo)(nil)

func NewCVERepository(queries *repository.Queries) *CVERepo {
	return &CVERepo{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *CVERepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *CVERepo) CreateOrUpdateCVE(ctx context.Context, vuln tools.Vulnerability) (*repository.CveDetail, error) {
	queries := r.getQueries(ctx)

	// --- Extract CVSS Metrics from vuln.Metrics slice ---
	var metricV20, metricV30, metricV31 *tools.CVSSMetric
	for i := range vuln.Metrics {
		m := vuln.Metrics[i]
		switch m.Version {
		case enums.CVSSv20:
			metricV20 = &m
		case enums.CVSSv30:
			metricV30 = &m
		case enums.CVSSv31:
			metricV31 = &m
		}
	}

	// 1. Store CVE detail of the vuln
	var err error

	params := repository.CreateCVEDetailParams{
		CveID: vuln.CveID,

		PublishedDate:    sql.NullTime{Time: vuln.Published, Valid: true},
		LastModifiedDate: sql.NullTime{Time: vuln.LastUpdated, Valid: true},

		Likelihood:     sql.NullString{String: vuln.Likelihood.String(), Valid: vuln.Likelihood.String() != ""},
		NvdDescription: sql.NullString{String: vuln.Description, Valid: vuln.Description != ""},
	}

	// --- CVSS v2 Metrics
	if metricV20 != nil {
		params.CvssV2Vector = stringToSQLNullString(metricV20.Access.String())
		params.CvssV2BaseScore = floatToSQLNullString(metricV20.BaseScore, "%.1f", true)
		params.CvssV2BaseSeverity = enumToSQLNullString(metricV20.Severity, func(e enums.SeverityType) bool { return e == "" })
		params.CvssV2ExploitabilityScore = floatToSQLNullString(metricV20.ExploitabilityScore, "%.1f", true)
		params.CvssV2ImpactScore = floatToSQLNullString(metricV20.ImpactScore, "%.1f", true)
		params.CvssV2AccessVector = enumToSQLNullString(metricV20.Access, func(e enums.AccessType) bool { return e == "" })
		params.CvssV2AccessComplexity = enumToSQLNullString(metricV20.Complexity, func(e enums.ComplexityType) bool { return e == "" })
		// TODO: We're missing these with ""?
		// params.CvssV2Authentication = stringToSQLNullString("")
		// params.CvssV2ConfidentialityImpact = stringToSQLNullString("")
		params.CvssV2IntegrityImpact = enumToSQLNullString(metricV20.IntegrityImpact, func(e enums.ImpactType) bool { return e == "" })
		params.CvssV2AvailabilityImpact = enumToSQLNullString(metricV20.AvailabilityImpact, func(e enums.ImpactType) bool { return e == "" })
	}

	// --- CVSS v3 Metrics
	if metricV30 != nil {
		params.CvssV30Vector = stringToSQLNullString(metricV30.Access.String())
		params.CvssV30BaseScore = floatToSQLNullString(metricV30.BaseScore, "%.1f", false)
		params.CvssV30BaseSeverity = stringToSQLNullString(metricV30.Severity.String())
		params.CvssV30ExploitabilityScore = floatToSQLNullString(metricV30.ExploitabilityScore, "%.1f", false)
		params.CvssV30ImpactScore = floatToSQLNullString(metricV30.ImpactScore, "%.1f", false)
		params.CvssV30AttackVector = enumToSQLNullString(metricV30.Access, func(e enums.AccessType) bool { return e == "" })
		params.CvssV30AttackComplexity = enumToSQLNullString(metricV30.Complexity, func(e enums.ComplexityType) bool { return e == "" })
		params.CvssV30PrivilegesRequired = enumToSQLNullString(metricV30.PrivilegesRequired, func(e enums.PrivilegesRequiredType) bool { return e == "" })
		// TODO: These are missing
		// params.CvssV30UserInteraction = ...
		// params.CvssV30Scope = ...
		// params.CvssV30ConfidentialityImpact = ...
		params.CvssV30IntegrityImpact = enumToSQLNullString(metricV30.IntegrityImpact, func(e enums.ImpactType) bool { return e == "" })
		params.CvssV30AvailabilityImpact = enumToSQLNullString(metricV30.AvailabilityImpact, func(e enums.ImpactType) bool { return e == "" })
	}

	// --- CVSS v31 Metrics
	if metricV31 != nil {
		// params.CvssV31Vector = stringToSQLNullString(metricV31.Vector)
		params.CvssV31BaseScore, err = floatToAPDNullDecimal(metricV31.BaseScore, "%.1f") // DECIMAL(3,1) format
		if err != nil {
			return nil, fmt.Errorf("mapping CvssV31BaseScore: %w", err)
		}
		params.CvssV31BaseSeverity = enumToSQLNullString(metricV31.Severity, func(e enums.SeverityType) bool { return e == enums.SeverityTypeUnknown || e == "" })
		params.CvssV31ExploitabilityScore, err = floatToAPDNullDecimal(metricV31.ExploitabilityScore, "%.1f")
		if err != nil {
			return nil, fmt.Errorf("mapping CvssV31ExploitabilityScore: %w", err)
		}
		params.CvssV31ExploitCodeMaturity = enumToSQLNullString(metricV31.Exploitability, func(e enums.ExploitabilityType) bool { return e == enums.ExploitabilityTypeUnknown || e == "" })
		params.CvssV31ImpactScore, err = floatToAPDNullDecimal(metricV31.ImpactScore, "%.1f")
		if err != nil {
			return nil, fmt.Errorf("mapping CvssV31ImpactScore: %w", err)
		}
		params.CvssV31AttackVector = stringToSQLNullString(metricV31.Access.String())
		params.CvssV31AttackComplexity = stringToSQLNullString(metricV31.Complexity.String())
		params.CvssV31PrivilegesRequired = stringToSQLNullString(metricV31.PrivilegesRequired.String())
		// params.CvssV31UserInteraction = ...
		// params.CvssV31Scope = ...
		// params.CvssV31ConfidentialityImpact = ...
		params.CvssV31IntegrityImpact = stringToSQLNullString(metricV31.IntegrityImpact.String())
		params.CvssV31AvailabilityImpact = stringToSQLNullString(metricV31.AvailabilityImpact.String())
	}

	// --- EPSS & RiskScore
	params.EpssPercentile = floatToSQLNullString(vuln.EPSSPercentile, "%.4f", true)
	params.EpssScore = floatToSQLNullString(vuln.EPSSScore, "%.2f", false)
	params.RiskScore, err = floatToAPDNullDecimal(vuln.RiskScore, "%.2f")
	if err != nil {
		return nil, fmt.Errorf("failed to map RiskScore: %w", err)
	}

	// --- JSONB Fields ---
	params.NvdReferences, err = marshalToPQNullRawMessage(vuln.References)
	if err != nil {
		return nil, fmt.Errorf("failed to map NvdReferences: %w", err)
	}
	params.VendorComments, err = marshalToPQNullRawMessage(vuln.VendorComments)
	if err != nil {
		return nil, fmt.Errorf("failed to map VendorComments: %w", err)
	}

	cveDetail, err := queries.CreateCVEDetail(ctx, params)
	return &cveDetail, err
}

func (r *CVERepo) GetCVEDetailsByID(ctx context.Context, cveID uuid.UUID) (*repository.CveDetail, error) {
	queries := r.getQueries(ctx)

	details, err := queries.GetCVEDetailByID(ctx, cveID)
	if err != nil {
		return &repository.CveDetail{}, err
	}
	return &details, nil
}

package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/cockroachdb/apd/v3"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
	"github.com/sqlc-dev/pqtype"
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

	// 1. Store CVE detail of the vuln
	baseCVSSScoreString := fmt.Sprintf("%.2f", vuln.BaseCVSSScore)
	baseScore, _, err := apd.NewFromString(baseCVSSScoreString)
	if err != nil {
		return nil, fmt.Errorf("failed to create decimal from string: %w", err)
	}
	exploitabilityScoreString := fmt.Sprintf("%.2f", vuln.Exploit.Score)
	exploitabilityScore, _, err := apd.NewFromString(exploitabilityScoreString)
	if err != nil {
		return nil, fmt.Errorf("failed to create exploitability score decimal from string: %w", err)
	}
	impactScoreString := fmt.Sprintf("%.2f", vuln.ImpactScore)
	impactScore, _, err := apd.NewFromString(impactScoreString)
	if err != nil {
		return nil, fmt.Errorf("failed to create impact score decimal from string: %w", err)
	}
	riskScoreString := fmt.Sprintf("%.2f", vuln.RiskScore)
	riskScore, _, err := apd.NewFromString(riskScoreString)
	if err != nil {
		return nil, fmt.Errorf("failed to create risk score decimal from string: %w", err)
	}

	referencesBytes, err := json.Marshal(vuln.References)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vuln references: %w", err)
	}
	vendorCommentsBytes, err := json.Marshal(vuln.VendorComments)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vuln vendor comments: %w", err)
	}

	params := repository.CreateCVEDetailParams{
		CveID:            vuln.CveID,
		Cwe:              vuln.Type.String(),
		SourceIdentifier: sql.NullString{},
		PublishedDate:    sql.NullTime{},
		LastModifiedDate: sql.NullTime{},
		VulnStatus:       sql.NullString{},

		// TODO: CVSS v2 Metrics go here

		// TODO: CVSS v3.0 Metrics go here

		CvssV31Vector:                sql.NullString{String: vuln.Access.String(), Valid: vuln.Access.String() != ""},
		CvssV31BaseScore:             apd.NullDecimal{Decimal: *baseScore, Valid: true},
		CvssV31BaseSeverity:          sql.NullString{String: vuln.BaseSeverity.String(), Valid: vuln.BaseSeverity.String() != ""},
		CvssV31ExploitabilityScore:   apd.NullDecimal{Decimal: *exploitabilityScore, Valid: true},
		CvssV31ExploitCodeMaturity:   sql.NullString{String: vuln.Exploit.Exploitability.String(), Valid: vuln.Exploit.Exploitability.String() != ""},
		CvssV31ImpactScore:           apd.NullDecimal{Decimal: *impactScore, Valid: true},
		CvssV31AttackVector:          sql.NullString{String: "", Valid: false},
		CvssV31AttackComplexity:      sql.NullString{String: vuln.Complexity.String(), Valid: vuln.Complexity.String() != ""},
		CvssV31PrivilegesRequired:    sql.NullString{String: vuln.PrivilegesRequired.String(), Valid: vuln.PrivilegesRequired.String() != ""},
		CvssV31UserInteraction:       sql.NullString{String: "", Valid: false},
		CvssV31Scope:                 sql.NullString{String: "", Valid: false},
		CvssV31ConfidentialityImpact: sql.NullString{String: "", Valid: false},
		CvssV31IntegrityImpact:       sql.NullString{String: vuln.IntegrityImpact.String(), Valid: vuln.IntegrityImpact.String() != ""},
		CvssV31AvailabilityImpact:    sql.NullString{String: vuln.AvailabilityImpact.String(), Valid: vuln.AvailabilityImpact.String() != ""},

		// TODO: Calculated metrics go here
		RiskScore:  apd.NullDecimal{Decimal: *riskScore, Valid: riskScore != nil},
		Likelihood: sql.NullString{String: vuln.Likelihood.String(), Valid: vuln.Likelihood.String() != ""},

		NvdDescription: sql.NullString{String: vuln.Description, Valid: vuln.Description != ""},
		NvdReferences:  pqtype.NullRawMessage{RawMessage: referencesBytes, Valid: true},
		VendorComments: pqtype.NullRawMessage{RawMessage: vendorCommentsBytes, Valid: true},
	}

	cveDetail, err := queries.CreateCVEDetail(ctx, params)
	return &cveDetail, err
}

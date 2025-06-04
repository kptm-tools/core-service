package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type VulnerRepo struct {
	db             *sql.DB
	defaultQueries *repository.Queries
}

var _ interfaces.VulnerabilityRepository = (*VulnerRepo)(nil)

func NewVulnerRepository(queries *repository.Queries, db *sql.DB) *VulnerRepo {
	return &VulnerRepo{
		defaultQueries: queries,
		db:             db,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *VulnerRepo) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *VulnerRepo) CreateVulnerability(
	ctx context.Context,
	hostID uuid.UUID,
	scanID uuid.UUID,
	vuln tools.Vulnerability,
	vulnType repository.VulnerabilityTypeEnum,
) (*tools.Vulnerability, error) {
	query := r.getQueries(ctx)

	params := repository.CreateVulnerabilityParams{
		HostID:         hostID,
		ScanID:         scanID,
		CveID:          sql.NullString{String: vuln.CveID, Valid: vuln.CveID != ""},
		Title:          vuln.CveID,
		Description:    sql.NullString{String: vuln.Description, Valid: vuln.Description != ""},
		Severity:       vuln.BaseSeverity.String(),
		VulnSource:     "NVD",
		VulnType:       vulnType,
		AnalystComment: sql.NullString{String: "", Valid: false},
	}
	dbVulner, err := query.CreateVulnerability(ctx, params)
	if err != nil {
		return nil, err
	}
	domVuln := toDomainVuln(dbVulner)
	return &domVuln, err
}

func (r *VulnerRepo) GetVulnerabilityByID(
	ctx context.Context,
	vulnID uuid.UUID,
) (*tools.Vulnerability, error) {
	queries := r.getQueries(ctx)
	dbVulner, err := queries.GetVulnerabilityWithCveDetailByID(ctx, vulnID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrVulnNotFound
		}
		return nil, fmt.Errorf("failed to query for vulnerability", err)
	}

	domVuln := toDomainVulnerabilityWithCveDetail(dbVulner)
	return &domVuln, nil
}

func (r *VulnerRepo) GetVulnerabilitiesWithCveDetailByScanID(ctx context.Context, scanID uuid.UUID) (
	[]tools.Vulnerability,
	error,
) {
	queries := r.getQueries(ctx)
	cveDetailedVulns, err := queries.GetVulnerabilitiesWithCveDetailsByScanID(ctx, scanID)
	if err != nil {
		return nil, err
	}

	domainVulns := make([]tools.Vulnerability, len(cveDetailedVulns))
	for i, cveDetailedVuln := range cveDetailedVulns {
		domainVulns[i] = toDomainVulnWithCveDetail(cveDetailedVuln)
	}
	return domainVulns, nil
}

func (r *VulnerRepo) UpdateVulnerabilityComment(ctx context.Context, vulnID uuid.UUID, newComment string) (bool, error) {
	queries := r.getQueries(ctx)
	params := repository.UpdateVulnerabilityCommentParams{
		ID:             vulnID,
		AnalystComment: sql.NullString{String: newComment, Valid: true},
	}
	_, err := queries.UpdateVulnerabilityComment(ctx, params)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *VulnerRepo) DeleteVulnerabilityComment(ctx context.Context, vulnID uuid.UUID) (bool, error) {
	queries := r.getQueries(ctx)
	_, err := queries.DeleteVulnerabilityComment(ctx, vulnID)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *VulnerRepo) HasComment(ctx context.Context, vulnID uuid.UUID) (bool, error) {
	queries := r.getQueries(ctx)
	vulnerStatus, err := queries.CheckVulnerabilityHasComment(ctx, vulnID)
	if err != nil {
		return false, err
	}

	hasComment, ok := vulnerStatus.HasComment.(bool)
	if !ok {
		return false, fmt.Errorf(
			"expected 'HasComment' to be of type bool, but got %T (value: %v)",
			vulnerStatus.HasComment,
			vulnerStatus.HasComment,
		)
	}
	return hasComment, nil
}

func (r *VulnerRepo) GetVulnerabilityType(ctx context.Context, vulnID uuid.UUID) (repository.VulnerabilityTypeEnum, error) {
	queries := r.getQueries(ctx)
	vuln, err := queries.GetVulnerabilityByID(ctx, vulnID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.VulnerabilityTypeEnumNETWORKOS, customerrors.ErrVulnNotFound
		}
		return repository.VulnerabilityTypeEnumNETWORKOS, err
	}
	return vuln.VulnType, nil
}

func (r *VulnerRepo) CreateNetworkOSVulnerabilityForOS(
	ctx context.Context,
	vulnID, scanID, hostID uuid.UUID,
	operatingSystemID int32,
) error {
	queries := r.getQueries(ctx)
	params := repository.CreateNetworkOSVulnerabilityParams{
		VulnerabilityID:   vulnID,
		ScanID:            scanID,
		HostID:            hostID,
		OperatingSystemID: sql.NullInt32{Int32: operatingSystemID, Valid: true},
		ServiceID:         sql.NullInt32{Valid: false},
	}
	_, err := queries.CreateNetworkOSVulnerability(ctx, params)
	return err
}

func (r *VulnerRepo) CreateNetworkOSVulnerabilityForService(
	ctx context.Context,
	vulnID, scanID, hostID uuid.UUID,
	serviceID int32,
) error {
	queries := r.getQueries(ctx)
	params := repository.CreateNetworkOSVulnerabilityParams{
		VulnerabilityID:   vulnID,
		ScanID:            scanID,
		HostID:            hostID,
		OperatingSystemID: sql.NullInt32{Valid: false},
		ServiceID:         sql.NullInt32{Int32: serviceID, Valid: false},
	}
	_, err := queries.CreateNetworkOSVulnerability(ctx, params)
	return err
}

func (r *VulnerRepo) GetNetworkOSVulnerability(ctx context.Context, vulnID uuid.UUID) (*domain.NetworkOSVulnerability, error) {
	queries := r.getQueries(ctx)
	dbNetOSVuln, err := queries.GetNetworkOSVulnerabilityByID(ctx, vulnID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrVulnNotFound
		}
	}

	// Handle nil values
	var osID, svcID *int32
	if dbNetOSVuln.OperatingSystemID.Valid {
		osID = &dbNetOSVuln.OperatingSystemID.Int32
	}
	if dbNetOSVuln.ServiceID.Valid {
		svcID = &dbNetOSVuln.ServiceID.Int32
	}

	domNetOSVuln := domain.NetworkOSVulnerability{
		VulnerabilityID:   dbNetOSVuln.VulnerabilityID,
		ScanID:            dbNetOSVuln.ScanID,
		HostID:            dbNetOSVuln.HostID,
		OperatingSystemID: osID,
		ServiceID:         svcID,
		CreatedAt:         &dbNetOSVuln.CreatedAt.Time,
		UpdatedAt:         &dbNetOSVuln.UpdatedAt.Time,
	}
	return &domNetOSVuln, nil
}

func (r *VulnerRepo) GetSeverityCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	queries := r.getQueries(ctx)

	dbCounts, err := queries.GetVulnerabilitySeverityCountsByScanID(ctx, scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tools.SeverityCounts{}, customerrors.ErrScanNotFound
		}
		return tools.SeverityCounts{}, err
	}

	counts := tools.SeverityCounts{
		Unknown:  int(dbCounts.UnknownVulnerabilities),
		None:     int(dbCounts.NoneVulnerabilities),
		Low:      int(dbCounts.LowVulnerabilities),
		Medium:   int(dbCounts.MediumVulnerabilities),
		High:     int(dbCounts.HighVulnerabilities),
		Critical: int(dbCounts.CriticalVulnerabilities),
	}
	return counts, nil
}

func (r *VulnerRepo) GetScanVulnerabilityAggregates(
	ctx context.Context,
	params domain.VulnerabilityAggregatesParams,
) (*domain.VulnerabilityAggregatesResult, error) {
	queries := r.getQueries(ctx)
	sqlcParams := repository.GetScanVulnerabilityAggregatesByScanIDParams{
		ScanID: params.ScanID,
	}
	if len(params.SeverityFilters) > 0 {
		sqlcParams.SeverityFilters = params.SeverityFilters
	} else {
		sqlcParams.SeverityFilters = nil
	}
	row, err := queries.GetScanVulnerabilityAggregatesByScanID(ctx, sqlcParams)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrScanNotFound
		}
		return nil, err
	}
	return &domain.VulnerabilityAggregatesResult{
		TotalVulnerabilities: int(row.TotalVulnerabilities),
		SeverityCounts: tools.SeverityCounts{
			Critical: int(row.CriticalVulnerabilities), High: int(row.HighVulnerabilities),
			Medium: int(row.MediumVulnerabilities), Low: int(row.MediumVulnerabilities),
			None: int(row.NoneVulnerabilities), Unknown: int(row.UnknownVulnerabilities),
		},
	}, nil
}

func (r *VulnerRepo) GetVulnerabilityCategoriesByScan(
	ctx context.Context,
	params domain.VulnerabilityCategoriesParams,
) ([]domain.ServiceCategoryData, error) {
	queries := r.getQueries(ctx)
	sqlcParams := repository.GetVulnerabilityCategoriesByScanParams{
		ScanID: params.ScanID,
	}
	if len(params.SeverityFilters) > 0 {
		sqlcParams.SeverityFilters = params.SeverityFilters
	} else {
		sqlcParams.SeverityFilters = nil
	}

	rows, err := queries.GetVulnerabilityCategoriesByScan(ctx, sqlcParams)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []domain.ServiceCategoryData{}, nil
		}
		return nil, err
	}
	categories := make([]domain.ServiceCategoryData, len(rows))
	for i, row := range rows {
		categories[i] = domain.ServiceCategoryData{
			Category: row.Category.String,
			Count:    int(row.Count),
		}
	}
	return categories, nil
}

func (r *VulnerRepo) GetHostVulnerabilityTrends(
	ctx context.Context,
	params domain.VulnerabilityTrendsParams,
) ([]domain.ServiceTimePeriod, error) {
	// This query is kind of complicated, but what it does is fill out time_periods and labels,
	// even when there is no data for said time_period. E.g: we only have data
	// for February, but we want to have the counts for other months to be 0 too.
	// It also has a CTE called ScanPeriods, which identifies if there was a scan at all
	// during that period. This allows us to differentiate if we got a 0 count because there
	// are no vulnerabilities, or because there is no scan.
	baseTrendQuery := `
		WITH TimePeriods AS (
			SELECT
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(date_series, 'FMMonth')
					WHEN $2 = 'Quarter' THEN 'Q' || TO_CHAR(date_series, 'Q')
					WHEN $2 = 'Semester' THEN 'Semester ' || CASE WHEN TO_CHAR(date_series, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE 'Unknown Period'
				END AS time_period_label,
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(date_series, 'YYYY-MM')
					WHEN $2 = 'Quarter' THEN TO_CHAR(date_series, 'YYYY-Q')
					WHEN $2 = 'Semester' THEN CASE WHEN TO_CHAR(date_series, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE '1'
				END AS ordering_period,
				date_series
			FROM generate_series(
				DATE_TRUNC('year', CURRENT_DATE),
				DATE_TRUNC('year', CURRENT_DATE) + INTERVAL '1 year' - INTERVAL '1 day',
				CASE
					WHEN $2 = 'Month' THEN INTERVAL '1 month'
					WHEN $2 = 'Quarter' THEN INTERVAL '3 month'
					WHEN $2 = 'Semester' THEN INTERVAL '6 month'
					ELSE INTERVAL '1 month'
				END
			) AS date_series
		),
		ScanPeriods AS (
			SELECT
        DISTINCT ON (time_period_label)
				CASE
					WHEN $2 = 'Month' THEN TO_CHAR(s.started_at, 'FMMonth')
					WHEN $2 = 'Quarter' THEN 'Q' || TO_CHAR(s.started_at, 'Q')
					WHEN $2 = 'Semester' THEN 'Semester ' || CASE WHEN TO_CHAR(s.started_at, 'MM')::integer <= 6 THEN '1' ELSE '2' END
					ELSE 'Unknown Period'
				END AS time_period_label,
				s.id AS scan_id,
				s.started_at AS scan_started_at
			FROM scans s
			WHERE s.host_id = $1
				AND EXTRACT(YEAR FROM s.started_at) = EXTRACT(YEAR FROM CURRENT_DATE)
      ORDER BY time_period_label, s.started_at DESC
		),
		VulnerabilityCounts AS (
			SELECT
				sp.time_period_label,
				COUNT(sv.id) AS vulnerability_count
			FROM ScanPeriods sp
			LEFT JOIN scan_vulnerabilities sv ON sv.scan_id = sp.scan_id
			INNER JOIN scans s ON sp.scan_id = s.id
			WHERE s.host_id = $1
				AND EXTRACT(YEAR FROM s.started_at) = EXTRACT(YEAR FROM CURRENT_DATE)
				-- Severity Filter Dynamic Condition goes here
				%s
			GROUP BY sp.time_period_label
		)
		SELECT
			tp.time_period_label AS time_period,
			vc.vulnerability_count AS vulnerability_count -- Now vc.vulnerability_count will be NULL if no scan
		FROM TimePeriods tp
		LEFT JOIN ScanPeriods sp ON tp.time_period_label = sp.time_period_label -- Join with ScanPeriods to ensure time period has a scan
		LEFT JOIN VulnerabilityCounts vc ON tp.time_period_label = vc.time_period_label
		ORDER BY tp.ordering_period;
	`

	trendQueryParams := []any{params.HostID, params.TimePeriodFilter.String()}
	trendSeverityWhereClause, trendQueryParams := buildSeverityWhereClause(params.SeverityFilters, trendQueryParams)
	forattedTrendQuery := fmt.Sprintf(baseTrendQuery, trendSeverityWhereClause)
	slog.Debug("Executing Host Trend Query",
		slog.Any("query_params", trendQueryParams))

	trendsRows, err := r.db.Query(forattedTrendQuery, trendQueryParams...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability trends for host %s: %w", params.HostID.String(), err)
	}
	defer trendsRows.Close()

	var timePeriods []domain.ServiceTimePeriod
	for trendsRows.Next() {
		var timePeriodData domain.ServiceTimePeriod
		if err := trendsRows.Scan(&timePeriodData.TimePeriod, &timePeriodData.VulnerabilityCount); err != nil {
			return nil, fmt.Errorf("failed to scan into time period: %w", err)
		}
		timePeriods = append(timePeriods, timePeriodData)
	}
	if trendsRows.Err() != nil {
		return nil, fmt.Errorf("failed to iterate trend rows: %w", err)
	}
	return timePeriods, nil
}

func toDomainVuln(dbVuln repository.Vulnerability) tools.Vulnerability {
	return tools.Vulnerability{
		ID:     dbVuln.ID,
		ScanID: dbVuln.ScanID,
		CveID:  dbVuln.CveID.String,
	}
}

// toDomainVulnerabilityWithCveDetail converts a sqlc-generated GetVulnerabilityWithCveDetailByIDRow
// into a domain.Vulnerability.
// It handles null values and type conversions.
func toDomainVulnerabilityWithCveDetail(dbVuln repository.GetVulnerabilityWithCveDetailByIDRow) tools.Vulnerability {
	// Initialize with direct assignments and default values
	domVuln := tools.Vulnerability{
		ID:          dbVuln.ID,
		HostID:      dbVuln.HostID,
		ScanID:      dbVuln.ScanID,
		CveID:       nullStringToString(dbVuln.CveID),
		Description: nullStringToString(dbVuln.Description),
		// Severity and VulnSource/Type are directly string in sqlc struct, no null check needed
		// but check if they should be enums in domain.
		AnalystComment: nullStringToString(dbVuln.AnalystComment),
		Published:      nullTimeToTime(dbVuln.PublishedDate),
		LastUpdated:    nullTimeToTime(dbVuln.LastModifiedDate),
		EPSSDate:       time.Time{}, // Not provided in sqlc row, default to zero value
	}

	// Map WeaknessType (VulnType)
	if vulnType, ok := enums.ParseWeaknessFromString(dbVuln.Cwe.String); ok {
		domVuln.Type = vulnType
	} else {
		slog.Warn("Unknown WeaknessType", slog.String("vuln_type", dbVuln.Cwe.String), slog.String("vuln_id", domVuln.ID.String()))
		domVuln.Type = enums.WeaknessNoInfo // Or another appropriate default
	}

	// Map CVSS v3.1 base score
	if baseCVSSScore, err := nullDecimalToFloat64(dbVuln.CvssV31BaseScore); err != nil {
		slog.Warn(
			"Could not parse CvssV31BaseScore",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.BaseCVSSScore = 0.0
	} else {
		domVuln.BaseCVSSScore = baseCVSSScore
	}

	// Map References
	if references, err := unmarshalNvdReferences(dbVuln.NvdReferences); err != nil {
		slog.Warn(
			"Could not parse NvdReferences",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.References = []string{}
	} else {
		domVuln.References = references
	}

	// Map CVSS v3.1 Attack Vector (Access)
	// Assuming enums.AccessType(string) is a safe conversion or needs parsing
	if dbVuln.CvssV31AttackVector.Valid {
		domVuln.Access = enums.AccessType(dbVuln.CvssV31AttackVector.String)
	} else {
		domVuln.Access = enums.AccessTypeUnknown
	}

	// Map CVSS v3.1 Attack Complexity (Complexity)
	if dbVuln.CvssV31AttackComplexity.Valid {
		domVuln.Complexity = enums.ComplexityType(dbVuln.CvssV31AttackComplexity.String)
	} else {
		domVuln.Complexity = enums.ComplexityTypeUnknown
	}

	// Map CVSS v3.1 Privileges Required
	if dbVuln.CvssV31PrivilegesRequired.Valid {
		domVuln.PrivilegesRequired = enums.PrivilegesRequiredType(dbVuln.CvssV31PrivilegesRequired.String)
	} else {
		domVuln.PrivilegesRequired = enums.PrivilegesRequiredUnknown
	}

	// Map Likelihood
	if dbVuln.Likelihood.Valid {
		domVuln.Likelihood = enums.LikelyhoodType(dbVuln.Likelihood.String)
	} else {
		domVuln.Likelihood = enums.LikelyhoodTypeUnknown
	}

	// Map RiskScore
	if riskScore, err := nullDecimalToFloat64(dbVuln.RiskScore); err != nil {
		slog.Warn(
			"Could not parse RiskScore",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.RiskScore = 0.0
	} else {
		domVuln.RiskScore = riskScore
	}

	// Map CVSS v3.1 Impact Score
	if impactScore, err := nullDecimalToFloat64(dbVuln.CvssV31ImpactScore); err != nil {
		slog.Warn(
			"Could not parse CvssV31ImpactScore",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.ImpactScore = 0.0
	} else {
		domVuln.ImpactScore = impactScore
	}

	// Map Exploit Score and Exploitability
	exploitScore, err := nullDecimalToFloat64(dbVuln.CvssV31ExploitabilityScore)
	if err != nil {
		slog.Warn(
			"Could not parse CvssV31ExploitabilityScore",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.Exploit.Score = 0.0
		domVuln.Exploit.Exploitability = enums.ExploitabilityTypeUnknown
	} else {
		domVuln.Exploit.Score = exploitScore
		if dbVuln.CvssV31ExploitCodeMaturity.Valid {
			domVuln.Exploit.Exploitability = enums.ExploitabilityType(dbVuln.CvssV31ExploitCodeMaturity.String)
		} else {
			domVuln.Exploit.Exploitability = enums.ExploitabilityTypeUnknown
		}
	}

	// Map CVSS v3.1 Integrity Impact
	if dbVuln.CvssV31IntegrityImpact.Valid {
		domVuln.IntegrityImpact = enums.ImpactType(dbVuln.CvssV31IntegrityImpact.String)
	} else {
		domVuln.IntegrityImpact = enums.ImpactTypeUnknown
	}

	// Map CVSS v3.1 Availability Impact
	if dbVuln.CvssV31AvailabilityImpact.Valid {
		domVuln.AvailabilityImpact = enums.ImpactType(dbVuln.CvssV31AvailabilityImpact.String)
	} else {
		domVuln.AvailabilityImpact = enums.ImpactTypeUnknown
	}

	// Map CVSS v3.1 Base Severity
	if dbVuln.CvssV31BaseSeverity.Valid {
		domVuln.BaseSeverity = enums.SeverityType(dbVuln.CvssV31BaseSeverity.String)
	} else {
		domVuln.BaseSeverity = enums.SeverityTypeUnknown
	}

	// Map Vendor Comments
	if vendorComments, err := unmarshalNvdVendorComments(dbVuln.VendorComments); err != nil {
		slog.Warn(
			"Could not parse vendor comments",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.VendorComments = []tools.VendorComment{}
	} else {
		domVuln.VendorComments = vendorComments
	}

	// Map EPSS Score
	if epssScore, err := parseNullStringAsFloat64(dbVuln.EpssScore); err != nil {
		slog.Warn(
			"Could not parse EPSS Score",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.EPSSScore = 0.0
	} else {
		domVuln.EPSSScore = epssScore
	}

	// Map EPSS Percentile
	if epssPercentile, err := parseNullStringAsFloat64(dbVuln.EpssPercentile); err != nil {
		slog.Warn(
			"Could not parse EPSS Percentile",
			slog.String("vuln_id", domVuln.ID.String()),
			slog.Any("error", err),
		)
		domVuln.EPSSPercentile = 0.0
	} else {
		domVuln.EPSSPercentile = epssPercentile
	}

	return domVuln
}

func toDomainVulnWithCveDetail(dbVuln repository.GetVulnerabilitiesWithCveDetailsByScanIDRow) tools.Vulnerability {
	domVuln := tools.Vulnerability{
		ID:             dbVuln.ID,
		HostID:         dbVuln.HostID,
		ScanID:         dbVuln.ScanID,
		CveID:          dbVuln.CveID.String,
		VendorComments: []tools.VendorComment{},
	}

	if dbVuln.CveID.Valid {
		domVuln.CveID = dbVuln.CveID.String
	} else {
		domVuln.CveID = ""
	}

	vulnCWE, ok := enums.ParseWeaknessFromString(dbVuln.Cwe.String)
	if ok {
		domVuln.Type = vulnCWE
	} else {
		domVuln.Type = enums.WeaknessNoInfo
	}

	baseCVSSScore, err := nullDecimalToFloat64(dbVuln.CvssV31BaseScore)
	if err != nil {
		slog.Warn(
			"Could not parse baseCVSSScore",
			slog.String("vuln_id", domVuln.CveID),
			slog.Any("error", err),
		)
		domVuln.BaseCVSSScore = 0.0
	} else {
		domVuln.BaseCVSSScore = baseCVSSScore
	}

	references, err := unmarshalNvdReferences(dbVuln.NvdReferences)
	if err != nil {
		slog.Warn(
			"Could not parse NvdReferences",
			slog.String("vuln_id", domVuln.CveID),
			slog.Any("error", err),
		)
		domVuln.References = []string{}
	} else {
		domVuln.References = references
	}

	if dbVuln.Description.Valid {
		domVuln.Description = dbVuln.Description.String
	} else {
		domVuln.Description = ""
	}

	if dbVuln.CvssV31AttackComplexity.Valid {
		// This cast could blow up in the future
		complexityType := enums.ComplexityType(dbVuln.CvssV31AttackComplexity.String)
		domVuln.Complexity = complexityType
	} else {
		domVuln.Complexity = enums.ComplexityTypeUnknown
	}

	if dbVuln.CvssV31PrivilegesRequired.Valid {
		privilegesRequired := enums.PrivilegesRequiredType(dbVuln.CvssV31PrivilegesRequired.String)
		domVuln.PrivilegesRequired = privilegesRequired
	} else {
		domVuln.PrivilegesRequired = enums.PrivilegesRequiredUnknown
	}

	if dbVuln.Likelihood.Valid {
		likelihood := enums.LikelyhoodType(dbVuln.Likelihood.String)
		domVuln.Likelihood = likelihood
	} else {
		domVuln.Likelihood = enums.LikelyhoodTypeUnknown
	}

	riskScore, err := nullDecimalToFloat64(dbVuln.RiskScore)
	if err != nil {
		slog.Warn(
			"Could not parse riskScore",
			slog.String("vuln_id", domVuln.CveID),
			slog.Any("error", err),
		)
		domVuln.RiskScore = 0.0
	} else {
		domVuln.RiskScore = riskScore
	}

	impactScore, err := nullDecimalToFloat64(dbVuln.CvssV31ImpactScore)
	if err != nil {
		slog.Warn(
			"Could not parse impactScore",
			slog.String("vuln_id", domVuln.CveID),
			slog.Any("error", err),
		)
		domVuln.ImpactScore = 0.0
	} else {
		domVuln.ImpactScore = impactScore
	}

	exploitScore, err := nullDecimalToFloat64(dbVuln.CvssV31ExploitabilityScore)
	if err != nil {
		slog.Warn(
			"Could not parse exploitScore",
			slog.String("vuln_id", domVuln.CveID),
			slog.Any("error", err),
		)
		domVuln.Exploit.Score = 0.0
		domVuln.Exploit.Exploitability = enums.ExploitabilityTypeUnknown
	} else {
		domVuln.Exploit.Score = exploitScore
		domVuln.Exploit.Exploitability = enums.ExploitabilityType(dbVuln.CvssV31ExploitCodeMaturity.String)
	}

	if dbVuln.CvssV31IntegrityImpact.Valid {
		domVuln.IntegrityImpact = enums.ImpactType(dbVuln.CvssV31IntegrityImpact.String)
	} else {
		domVuln.IntegrityImpact = enums.ImpactTypeUnknown
	}

	if dbVuln.CvssV31AvailabilityImpact.Valid {
		domVuln.AvailabilityImpact = enums.ImpactType(dbVuln.CvssV31AvailabilityImpact.String)
	} else {
		domVuln.AvailabilityImpact = enums.ImpactTypeUnknown
	}

	if dbVuln.CvssV31BaseSeverity.Valid {
		domVuln.BaseSeverity = enums.SeverityType(dbVuln.CvssV31BaseSeverity.String)
	} else {
		domVuln.BaseSeverity = enums.SeverityTypeUnknown
	}

	if dbVuln.AnalystComment.Valid {
		domVuln.AnalystComment = dbVuln.AnalystComment.String
	} else {
		domVuln.AnalystComment = ""
	}

	vendorComments, err := unmarshalNvdVendorComments(dbVuln.VendorComments)
	if err != nil {
		slog.Warn(
			"Could not parse vendor comments",
			slog.String("vuln_id", domVuln.CveID),
			slog.Any("error", err),
		)
		domVuln.VendorComments = []tools.VendorComment{}
	} else {
		domVuln.VendorComments = vendorComments
	}

	if dbVuln.PublishedDate.Valid {
		domVuln.Published = dbVuln.PublishedDate.Time
	}

	if dbVuln.LastModifiedDate.Valid {
		domVuln.LastUpdated = dbVuln.LastModifiedDate.Time
	}

	return domVuln
}

func buildSeverityWhereClause(severityFilters []string, queryParams []any) (string, []any) {
	severityWhereClause := ""
	if len(severityFilters) > 0 {
		placeholders := make([]string, len(severityFilters))
		for i, severity := range severityFilters {
			placeholders[i] = fmt.Sprintf("$%d", len(queryParams)+1)
			queryParams = append(queryParams, severity)
		}
		severityWhereClause = fmt.Sprintf("AND sv.severity ILIKE ANY(array[%s])", strings.Join(placeholders, ","))
	}

	return severityWhereClause, queryParams
}

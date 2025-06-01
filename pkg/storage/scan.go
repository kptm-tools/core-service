package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cockroachdb/apd/v3"
	"github.com/lib/pq"
	"github.com/sqlc-dev/pqtype"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/repository"
)

func (s *PostgreSQLStore) ClearScanTable() error {
	query := `TRUNCATE TABLE scans RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) ClearScanResultsTable() error {
	query := `TRUNCATE TABLE scan_results RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) ClearScanVulnerabilitiesTable() error {
	query := `TRUNCATE TABLE scan_vulnerabilities RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateScan(sc *domain.Scan) (*domain.Scan, error) {
	var insertedScan domain.Scan
	query := `
    INSERT INTO scans (tenant_id, operator_id, host_id, status, started_at)
                values ($1, $2, $3, $4, $5)
    RETURNING id, tenant_id, operator_id, host_id, status, started_at`

	err := s.db.QueryRow(query, sc.TenantID, sc.OperatorID, sc.HostID, sc.Status, sc.StartedAt).Scan(
		&insertedScan.ID,
		&insertedScan.TenantID,
		&insertedScan.OperatorID,
		&insertedScan.HostID,
		&insertedScan.Status,
		&insertedScan.StartedAt,
	)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23503" && pqErr.Constraint == "scans_host_id_fkey" {
				return nil, customerrors.ErrScanHostFKNotFound
			}
		}
		return nil, fmt.Errorf("failed to insert scan: %w", err)
	}

	return &insertedScan, nil
}

func (s *PostgreSQLStore) InsertVulnerabilityResult(ctx context.Context, sr *domain.ScanResult) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()
	qtx := s.queries.WithTx(tx)

	if sr.Result.Tool != enums.ToolNmap {
		return fmt.Errorf("scan result tool is invalid: %s", sr.Result.Tool)
	}

	scan, err := qtx.GetScanByID(ctx, sr.ScanID)
	if err != nil {
		return fmt.Errorf("failed to fetch scan by ID: %w", err)
	}

	// 1. Parse vulnerabilities and store them to vulnerabilities
	if sr.Result.Err != nil {
		slog.Warn("Vulnerability scan has errors, skipping vulnerability insertion")
		return nil
	}

	// 2. Unmarshal the result to a tools.NmapResult variable
	var nr tools.NmapResult
	resultBytes, err := json.Marshal(sr.Result.Result)
	if err != nil {
		return fmt.Errorf("failed to marshal nmap result: %w", err)
	}
	err = json.Unmarshal(resultBytes, &nr)
	if err != nil {
		return fmt.Errorf("failed to unmarshal nmap result: %w", err)
	}

	// 1. Store OS (if OS data is present in scanResult)
	if err := s.InsertOSVulnerabilities(ctx, qtx, scan, nr.MostLikelyOS); err != nil {
		return fmt.Errorf("failed to insert OS vulnerabilities for scan %s: %w", scan.ID.String(), err)
	}

	// 2. Insert Service Vulners
	for _, portData := range nr.ScannedPorts {
		if err := s.InsertPortVulnerabilities(ctx, qtx, scan, portData); err != nil {
			return fmt.Errorf("failed to insert service vulnerabilities for scan %s: %w", scan.ID.String(), err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *PostgreSQLStore) InsertOSVulnerabilities(
	ctx context.Context,
	qtx *repository.Queries,
	scan repository.Scan,
	osData tools.OSData,
) error {
	// 1. Store or Update OS
	params := repository.CreateOSParams{
		HostID: scan.HostID.UUID,
		ScanID: scan.ID,
		OsName: sql.NullString{String: osData.Name, Valid: osData.Name != ""},
		Family: sql.NullString{String: osData.Family, Valid: osData.Family != ""},
		OsType: sql.NullString{String: osData.Type, Valid: osData.Type != ""},
	}
	operatingSystem, err := qtx.CreateOS(ctx, params)
	if err != nil {
		return fmt.Errorf("failed to store OS data: %w", err)
	}

	// 2. Loop through each vulnerability, saving each one
	for _, vuln := range osData.Vulnerabilities {

		// 2.1 Store CVE detail of the vuln
		_, err = s.InsertCVEDetail(ctx, qtx, vuln)
		if err != nil {
			return fmt.Errorf("failed to insert os vulnerability CVE Detail: %w", err)
		}

		// 2.2 Create Vulnerability record
		createVulnerParams := repository.CreateVulnerabilityParams{
			HostID:         scan.HostID.UUID,
			ScanID:         scan.ID,
			CveID:          sql.NullString{String: vuln.CveID, Valid: vuln.CveID != ""},
			Title:          vuln.CveID,
			Description:    sql.NullString{String: vuln.Description, Valid: vuln.Description != ""},
			Severity:       vuln.BaseSeverity.String(),
			VulnSource:     "NVD",
			VulnType:       repository.VulnerabilityTypeEnumNETWORKOS,
			AnalystComment: sql.NullString{String: "", Valid: false},
		}
		dbVulner, err := qtx.CreateVulnerability(ctx, createVulnerParams)
		if err != nil {
			return fmt.Errorf("failed to create vulnerablity record: %w", err)
		}

		// 3. Create NetworkOS Vulnerability Record
		networkOSVulnerabilityParams := repository.CreateNetworkOSVulnerabilityParams{
			VulnerabilityID:   dbVulner.ID,
			ScanID:            scan.ID,
			HostID:            scan.HostID.UUID,
			OperatingSystemID: sql.NullInt32{Int32: operatingSystem.ID, Valid: true},
			ServiceID:         sql.NullInt32{Valid: false},
		}
		_, err = qtx.CreateNetworkOSVulnerability(ctx, networkOSVulnerabilityParams)
		if err != nil {
			return fmt.Errorf("failed to create network os vulnerability record: %w", err)
		}

	}

	return nil
}

func (s *PostgreSQLStore) InsertPortVulnerabilities(
	ctx context.Context,
	qtx *repository.Queries,
	scan repository.Scan,
	portData tools.PortData,
) error {
	// 1. Store Service
	createOrUpdateParams := repository.CreateOrUpdateServiceParams{
		HostID:     scan.HostID.UUID,
		ScanID:     scan.ID,
		Port:       int32(portData.ID),
		Protocol:   sql.NullString{String: portData.Protocol, Valid: portData.Protocol != ""},
		SvName:     sql.NullString{String: portData.Service.Name, Valid: portData.Service.Name != ""},
		SvVersion:  sql.NullString{String: portData.Service.Version, Valid: portData.Service.Version != ""},
		Confidence: sql.NullInt32{Int32: int32(portData.Service.Confidence), Valid: portData.Service.Confidence != 0},
		Cpe:        sql.NullString{String: portData.Service.CPE, Valid: portData.Service.CPE != ""},
		Product:    sql.NullString{String: portData.Product, Valid: portData.Product != ""},
		PortState:  repository.PortStateEnum(portData.State),
	}
	service, err := qtx.CreateOrUpdateService(ctx, createOrUpdateParams)
	if err != nil {
		return fmt.Errorf("failed to create or update service: %w", err)
	}

	slog.Debug(
		"Service processed (created or updated)",
		slog.String("scan_id", scan.ID.String()),
		slog.String("service_cpe", portData.Service.CPE),
		slog.Int("service_port", int(portData.ID)),
	)

	// 2. Store vulnerabilities associated to the service
	for _, vuln := range portData.Vulnerabilities {

		// 2.1 Store CVE detail, look up if it exists first
		_, err = s.InsertCVEDetail(ctx, qtx, vuln)
		if err != nil {
			return fmt.Errorf("failed to insert cve detail record: %w", err)
		}

		// 2.2 Store Vulnerability Record
		createVulnerParams := repository.CreateVulnerabilityParams{
			HostID:         scan.HostID.UUID,
			ScanID:         scan.ID,
			CveID:          sql.NullString{String: vuln.CveID, Valid: vuln.CveID != ""},
			Title:          vuln.CveID,
			Description:    sql.NullString{String: vuln.Description, Valid: vuln.Description != ""},
			Severity:       vuln.BaseSeverity.String(),
			VulnType:       repository.VulnerabilityTypeEnumNETWORKOS,
			VulnSource:     "NVD",
			AnalystComment: sql.NullString{String: "", Valid: false},
		}
		dbVulner, err := qtx.CreateVulnerability(ctx, createVulnerParams)
		if err != nil {
			return fmt.Errorf("failed to create vulnerablity record: %w", err)
		}

		// 2.3 Store NetworkOS vulnerability record
		networkOSVulnerabilityParams := repository.CreateNetworkOSVulnerabilityParams{
			VulnerabilityID:   dbVulner.ID,
			ScanID:            scan.ID,
			HostID:            scan.HostID.UUID,
			OperatingSystemID: sql.NullInt32{Valid: false},
			ServiceID:         sql.NullInt32{Int32: service.ID, Valid: service.ID >= 0},
		}
		_, err = qtx.CreateNetworkOSVulnerability(ctx, networkOSVulnerabilityParams)
		if err != nil {
			return fmt.Errorf("failed to create network os vulnerability record: %w", err)
		}

	}
	return nil
}

func (s *PostgreSQLStore) InsertCVEDetail(ctx context.Context, qtx *repository.Queries, vuln tools.Vulnerability) (*repository.CveDetail, error) {
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
		CvssV31ImpactScore:           apd.NullDecimal{Decimal: *impactScore, Valid: true},
		CvssV31AttackVector:          sql.NullString{String: "", Valid: false},
		CvssV31AttackComplexity:      sql.NullString{String: vuln.Complexity.String(), Valid: vuln.Complexity.String() != ""},
		CvssV31PrivilegesRequired:    sql.NullString{String: vuln.PrivilegesRequired.String(), Valid: vuln.PrivilegesRequired.String() != ""},
		CvssV31UserInteraction:       sql.NullString{String: "", Valid: false},
		CvssV31Scope:                 sql.NullString{String: "", Valid: false},
		CvssV31ConfidentialityImpact: sql.NullString{String: "", Valid: false},
		CvssV31IntegrityImpact:       sql.NullString{String: vuln.IntegrityImpact.String(), Valid: vuln.IntegrityImpact.String() != ""},
		CvssV31AvailabilityImpact:    sql.NullString{String: vuln.AvailabilityImpact.String(), Valid: vuln.AvailabilityImpact.String() != ""},

		NvdDescription: sql.NullString{String: vuln.Description, Valid: vuln.Description != ""},
		NvdReferences:  pqtype.NullRawMessage{RawMessage: referencesBytes, Valid: true},
		VendorComments: pqtype.NullRawMessage{RawMessage: vendorCommentsBytes, Valid: true},
	}

	cveDetail, err := qtx.CreateCVEDetail(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create CVE detail entry: %w", err)
	}
	return &cveDetail, nil
}

func scanIntoScanSum(rows *sql.Rows) (*domain.ScanSummary, error) {
	scanSum := new(domain.ScanSummary)
	err := rows.Scan(
		&scanSum.ScanID,
		&scanSum.ScanDate,
		&scanSum.Host,
		&scanSum.Duration,
		&scanSum.Status,
		&scanSum.Vulnerabilities,
		&scanSum.Severities.Low,
		&scanSum.Severities.Medium,
		&scanSum.Severities.High,
		&scanSum.Severities.Critical,
	)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Scan: %w", err)
	}

	return scanSum, nil
}

func (s *PostgreSQLStore) GetCurrentScans(tenantID string) ([]*domain.ScanSummary, error) {
	query := `
  WITH aggregated_vulnerabilities AS (
    SELECT
      S.id AS scan_id,
      COUNT(V.id) AS total_vulnerabilities,
      SUM(CASE WHEN V.severity = 'Low' THEN 1 ELSE 0 END) AS low,
      SUM(CASE WHEN V.severity = 'Medium' THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN V.severity = 'High' THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN V.severity = 'Critical' THEN 1 ELSE 0 END) AS critical
    FROM scans S
    LEFT JOIN scan_vulnerabilities V ON S.id = V.scan_id
    WHERE S.tenant_id = $1
    GROUP BY S.id
  )
    SELECT
      S.id AS scan_id,
      S.started_at AS scan_date,
      H.alias AS host,
      EXTRACT(epoch from COALESCE(S.ended_at, NOW()) - S.started_at) as duration_in_seconds,
      S.status,
      COALESCE(total_vulnerabilities, 0) as total_vulnerabilities,
      COALESCE(A.low, 0) AS low,
      COALESCE(A.medium, 0) AS medium,
      COALESCE(A.high, 0) AS high,
      COALESCE(A.critical, 0) AS critical
   FROM  scans S
   INNER JOIN hosts H ON S.host_id = H.id
   LEFT JOIN aggregated_vulnerabilities A ON S.id = A.scan_id
   WHERE S.tenant_id = $1 and status!=$2
   ORDER BY S.started_at DESC`

	rows, err := s.db.Query(query, tenantID, enums.StatusScheduled.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scans: %w", err)
	}
	defer rows.Close()

	scans := []*domain.ScanSummary{}
	for rows.Next() {
		scanSum, err := scanIntoScanSum(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan into summary: %w", err)
		}
		scans = append(scans, scanSum)
	}

	return scans, nil
}

func (s *PostgreSQLStore) GetScanByID(UUID uuid.UUID) (*domain.Scan, error) {
	query := `
    SELECT id, tenant_id, operator_id, host_id, status, started_at, ended_at, created_at, updated_at
    FROM scans
    WHERE id = $1
  `

	var scan domain.Scan
	err := s.db.QueryRow(query, UUID).Scan(
		&scan.ID,
		&scan.TenantID,
		&scan.OperatorID,
		&scan.HostID,
		&scan.Status,
		&scan.StartedAt,
		&scan.EndedAt,
		&scan.CreatedAt,
		&scan.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrScanNotFound
		}
		return nil, fmt.Errorf("error scanning scan: %w", err)
	}

	return &scan, nil
}

func (s *PostgreSQLStore) InsertScanResult(tx *sql.Tx, sr *domain.ScanResult) error {
	query := `
    INSERT INTO scan_results (scan_id, tool, success, result, created_at)
    values ($1, $2, $3, $4, $5)`

	toolName := string(sr.Result.Tool)

	resultBytes, err := json.Marshal(sr.Result.Result)
	if err != nil {
		return fmt.Errorf("error marshalling scan result: %w", err)
	}

	if tx != nil {
		_, err = tx.Exec(query, sr.ScanID, toolName, sr.Success, resultBytes, sr.CreatedAt)
	} else {
		_, err = s.db.Exec(query, sr.ScanID, toolName, sr.Success, resultBytes, sr.CreatedAt)
	}

	if err != nil {
		return fmt.Errorf("failed to insert scan_results: %w", err)
	}

	return nil
}

func (s *PostgreSQLStore) UpdateScanStatus(scanID uuid.UUID, status string) error {
	query := `UPDATE scans
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE scan_id = $2`
	result, err := s.db.Exec(query, status, scanID)
	if err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to retrieve affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan with id %s not found", scanID.String())
	}

	return nil
}

func (s *PostgreSQLStore) UpdateScanStatusAndEndedAt(tx *sql.Tx, scanID uuid.UUID, status string, endedAt time.Time) error {
	query := `UPDATE scans
            SET status = $1, updated_at = CURRENT_TIMESTAMP, ended_at = $2
            WHERE id = $3`

	execFunc := func(query string, args ...interface{}) (sql.Result, error) {
		if tx != nil {
			return tx.Exec(query, args...)
		} else {
			return s.db.Exec(query, args...)
		}
	}

	result, err := execFunc(query, status, endedAt, scanID)
	if err != nil {
		return fmt.Errorf("failed to update scan status and ended_at: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to retrieve affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan with id %s not found", scanID.String())
	}

	return nil
}

func (s *PostgreSQLStore) GetScanInsights(scanID uuid.UUID) (*domain.ScanInsights, error) {
	query := `
    WITH severity_per_type AS (
      SELECT
        sv.type AS vuln_type,
        MAX(sv.cvss) AS max_cvss
      FROM
        scan_vulnerabilities sv
      WHERE
        sv.scan_id = $1
      GROUP BY
        sv.type
  )
    SELECT
      scans.id AS scan_id,
      hosts.alias AS scan_alias,
      scans.started_at AS scan_date,
      COUNT(sv.id) AS total_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'Low' THEN 1 ELSE 0 END) AS low_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'Medium' THEN 1 ELSE 0 END) as medium_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'High' THEN 1 ELSE 0 END) as high_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_vulnerabilities,
      (
        SELECT json_object_agg(
          vuln_type,
          max_cvss
        )
        FROM severity_per_type
      ) AS severity_per_type_map
    
    FROM
      scans
    INNER JOIN hosts ON scans.host_id = hosts.id
    LEFT JOIN
      scan_vulnerabilities sv ON scans.id = sv.scan_id
    WHERE
      scans.id = $1
    GROUP BY scans.id, hosts.alias, scans.started_at;
  `

	rows := s.db.QueryRow(query, scanID)

	var insights domain.ScanInsights
	var severityPerTypeJSON []byte

	err := rows.Scan(
		&insights.Metadata.ScanID,
		&insights.Metadata.HostAlias,
		&insights.Metadata.ScanDate,
		&insights.TotalVulnerabilities,
		&insights.SeverityCounts.Low,
		&insights.SeverityCounts.Medium,
		&insights.SeverityCounts.High,
		&insights.SeverityCounts.Critical,
		&severityPerTypeJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	// Parse JSON severity_per_type into the desired map if there are vulnerabilities
	var severityPerType map[string]float64

	if insights.TotalVulnerabilities > 0 {
		if err := json.Unmarshal(severityPerTypeJSON, &severityPerType); err != nil {
			return nil, fmt.Errorf("failed to unmarshal severity_per_type JSON: %w", err)
		}
	}

	// Map max cvss values into enums.Severity
	mapSeverities := func(a map[string]float64, f func(float64) string) map[string]string {
		n := make(map[string]string, len(a))
		for k, v := range a {
			n[k] = f(v)
		}
		return n
	}

	insights.SeverityPerType = mapSeverities(severityPerType, func(s float64) string {
		return tools.MapCVSS(s).String()
	})
	// 1. Calculate total_vulnerabilities variation since last scan
	vulnerabilityVariation, err := s.GetTotalVulnerabilityVariationSinceLastScan(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get total vulnerability variation: %w", err)
	}
	insights.VulnerabilityVariation = vulnerabilityVariation

	// 2. Calculate protection_score
	protectionScore, err := s.GetProtectionScore(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get protection score: %w", err)
	}
	insights.ProtectionScore = protectionScore

	// 3. Calculate protection_score variation since last scan
	prevScan, err := s.GetPreviousScan(scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			insights.ProtectionScoreVariation = 0.0
			return &insights, nil
		}
		return nil, fmt.Errorf("failed to fetch previous scan: %w", err)
	}

	// Calculate protectionScore Variation
	var protectionScoreVariation float64
	if !prevScan.IsFailedOrCancelled() {
		prevProtectionScore, err := s.GetProtectionScore(prevScan.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get previous scan's protection score: %w", err)
		}
		protectionScoreVariation = insights.ProtectionScore - prevProtectionScore
	}

	insights.ProtectionScoreVariation = protectionScoreVariation
	return &insights, nil
}

func (s *PostgreSQLStore) GetTotalVulnerabilityVariationSinceLastScan(scanID uuid.UUID) (int, error) {
	// 1. Get the HostID for the current scan
	var hostID int
	var currentScanCreatedAt time.Time
	query := `
    SELECT host_id, created_at
    FROM scans
    WHERE id = $1
  `
	err := s.db.QueryRow(query, scanID).Scan(&hostID, &currentScanCreatedAt)
	if err != nil {
		return 0, fmt.Errorf("failed to get host_id and created_at for the current scan: %w", err)
	}

	// 2. Get the last scan's vulnerabilities for the same host
	var lastScanVulns int
	query = `
    SELECT COUNT(V.id)
    FROM scan_vulnerabilities V
    JOIN scans S ON S.id = V.scan_id
    WHERE S.host_id = $1
    AND S.created_at < $2
    ORDER BY MAX(S.created_at) DESC
    LIMIT 1`
	err = s.db.QueryRow(query, hostID, currentScanCreatedAt).Scan(&lastScanVulns)
	if err != nil {
		if err == sql.ErrNoRows {
			// There is no last scan, which means that the variation is 0
			slog.Debug("No last scan found", slog.Int("host_id", hostID), slog.Time("current_scan_created_at", currentScanCreatedAt))
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get the last scan's total vulnerabilities: %w", err)
	}

	slog.Debug("Last scan's total vulns", slog.Int("total_vulnerabilities", lastScanVulns))

	// 3. Get the current scan's vulnerabilities
	var currentScanVulns int
	query = `
    SELECT count(V.id)
    FROM scan_vulnerabilities V
    WHERE V.scan_id = $1
  `
	err = s.db.QueryRow(query, scanID).Scan(&currentScanVulns)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("scan does not exist: %w", err)
		}
		return 0, fmt.Errorf("failed to get the current scan's total vulnerabilities: %w", err)
	}

	slog.Debug("Current scan's total vulns", slog.Int("total_vulnerabilities", currentScanVulns))

	// 4. Calculate the vulnerability variation
	return currentScanVulns - lastScanVulns, nil
}

func (s *PostgreSQLStore) GetPreviousScan(scanID uuid.UUID) (*domain.Scan, error) {
	var createdAt time.Time
	var hostID string
	query := `SELECT created_at, host_id FROM scans WHERE id = $1`
	err := s.db.QueryRow(query, scanID).Scan(&createdAt, &hostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current scan's created_at: %w", err)
	}

	var scan domain.Scan
	query = `
    SELECT id, tenant_id, operator_id, host_id, status, started_at, ended_at, created_at, updated_at
    FROM scans
    WHERE created_at < $1 AND host_id = $2
    ORDER BY created_at DESC
    LIMIT 1`

	err = s.db.QueryRow(query, createdAt, hostID).Scan(
		&scan.ID, &scan.TenantID, &scan.OperatorID, &scan.HostID, &scan.Status, &scan.StartedAt, &scan.EndedAt, &scan.CreatedAt, &scan.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	slog.Debug("Got previous scan", slog.Any("prev_scan", scan))

	return &scan, nil
}

// GetToolResults is a generic function that parses a ToolResult from the scan_results
// result column. It uses generics to be extensible and ensure type safety.
func GetToolResults[T tools.IToolResult](s *PostgreSQLStore, scanID uuid.UUID) (T, error) {
	var toolResult T

	toolName := string(toolResult.GetToolName())

	var toolResultBytes []byte
	query := `
    SELECT result
    FROM scan_results
    WHERE scan_id = $1 AND tool = $2
  `
	if err := s.db.QueryRow(query, scanID, toolName).Scan(&toolResultBytes); err != nil {
		return toolResult, fmt.Errorf("failed to fetch %s results: %w", string(toolName), err)
	}

	if err := json.Unmarshal(toolResultBytes, &toolResult); err != nil {
		return toolResult, fmt.Errorf("failed to unmarshal ToolResult for %s: %w", string(toolName), err)
	}

	slog.Debug("Got Tool Result from DB",
		slog.String("scan_id", scanID.String()),
		slog.String("tool_name", string(toolName)),
		slog.Any("tool_result", toolResult))

	return toolResult, nil
}

func (s *PostgreSQLStore) GetWhoisResult(scanID uuid.UUID) (*tools.WhoIsResult, error) {
	return GetToolResults[*tools.WhoIsResult](s, scanID)
}

func (s *PostgreSQLStore) GetDNSLookupResult(scanID uuid.UUID) (*tools.DNSLookupResult, error) {
	return GetToolResults[*tools.DNSLookupResult](s, scanID)
}

func (s *PostgreSQLStore) GetHarvesterResult(scanID uuid.UUID) (*tools.HarvesterResult, error) {
	return GetToolResults[*tools.HarvesterResult](s, scanID)
}

func (s *PostgreSQLStore) GetNmapResult(scanID uuid.UUID) (*tools.NmapResult, error) {
	return GetToolResults[*tools.NmapResult](s, scanID)
}

func (s *PostgreSQLStore) GetProtectionScore(scanID uuid.UUID) (float64, error) {
	var protectionScore float64
	query := `SELECT protection_score FROM scans WHERE id=$1`
	err := s.db.QueryRow(query, scanID).Scan(&protectionScore)
	if err != nil {
		return 0, fmt.Errorf("error scanning into protectionScore: %w", err)
	}

	return protectionScore, nil
}

func (s *PostgreSQLStore) UpdateProtectionScore(scanID uuid.UUID, protectionScore float64) error {
	query := `UPDATE scans SET protection_score=$1, updated_at=now() WHERE id=$2`
	res, err := s.db.Exec(query, protectionScore, scanID)
	if err != nil {
		return fmt.Errorf("failed to execute query: %w", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to fetch affected rows: %w", err)
	}

	if rowsAffected < 1 {
		slog.Warn("UpdateProtectionScore affected no scans", slog.String("scan_id", scanID.String()))
	}
	return nil
}

func (s *PostgreSQLStore) GetScanVulnerabilitiesSummary(
	scanID uuid.UUID,
	timePeriodFilter domain.TimePeriodFilter,
	severityFilters []string,
) (*domain.ScanVulnerabilitySummaryData, error) {
	var summaryData domain.ScanVulnerabilitySummaryData
	summaryData.ScanID = scanID

	// 0. Get Host Alias
	var hostAlias string
	aliasQuery := `
    SELECT hosts.alias
    FROM hosts
    INNER JOIN scans ON scans.host_id = hosts.id
    WHERE scans.id = $1
  `
	err := s.db.QueryRow(aliasQuery, scanID).Scan(&hostAlias)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch host alias: %w", err)
	}
	summaryData.Domain = hostAlias

	// 1. Get vulnerabilities
	baseSummaryQuery := `
    SELECT 
      scans.id AS scan_id,
      hosts.alias AS host_alias,
      COUNT(sv.id) AS total_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'Low' THEN 1 ELSE 0 END) AS low_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'Medium' THEN 1 ELSE 0 END) as medium_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'High' THEN 1 ELSE 0 END) as high_vulnerabilities,
      SUM(CASE WHEN sv.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_vulnerabilities
  FROM
    scans
  INNER JOIN hosts ON scans.host_id = hosts.id
  LEFT JOIN
    scan_vulnerabilities sv ON scans.id = sv.scan_id
  WHERE scans.id = $1
    -- Severity Filter Dynamic Condition goes here
    %s
  GROUP BY scans.id, hosts.alias;
  `

	summaryQueryParams := []any{scanID}
	summarySeverityWhereClause, summaryQueryParams := s.buildSeverityWhereClause(severityFilters, summaryQueryParams)
	formattedSummaryQuery := fmt.Sprintf(baseSummaryQuery, summarySeverityWhereClause)
	slog.Debug("Executing Summary Query",
		slog.Any("query_params", summaryQueryParams))

	err = s.db.QueryRow(formattedSummaryQuery, summaryQueryParams...).Scan(
		&summaryData.ScanID,
		&summaryData.Domain,
		&summaryData.TotalVulnerabilities,
		&summaryData.SeverityCounts.Low,
		&summaryData.SeverityCounts.Medium,
		&summaryData.SeverityCounts.High,
		&summaryData.SeverityCounts.Critical,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.Warn("No rows were found", slog.String("scan_id", scanID.String()))
			return &summaryData, nil
		}
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	// Handling Categories and Trends
	// 1. Fetch category data
	baseCategoryQuery := `
    SELECT
      sv.type AS category,
      COUNT(sv.type) AS category_count
    FROM 
      scan_vulnerabilities sv
    WHERE sv.scan_id = $1
    -- Severity Filter Dynamic Condition goes here
    %s
    GROUP BY sv.type;
  `

	categoryQueryParams := []any{scanID}
	categorySeverityWhereClause, categoryQueryParams := s.buildSeverityWhereClause(severityFilters, categoryQueryParams)
	formattedCategoryQuery := fmt.Sprintf(baseCategoryQuery, categorySeverityWhereClause)
	slog.Debug("Executing Category Query",
		slog.Any("query_params", categoryQueryParams))

	categoryRows, err := s.db.Query(formattedCategoryQuery, categoryQueryParams...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability categories: %w", err)
	}
	defer categoryRows.Close()

	var categoryData []domain.ServiceCategoryData
	for categoryRows.Next() {
		var catData domain.ServiceCategoryData
		if err := categoryRows.Scan(&catData.Category, &catData.Count); err != nil {
			return nil, fmt.Errorf("failed to scan into category data: %w", err)
		}
		categoryData = append(categoryData, catData)
	}
	if err := categoryRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate category rows: %w", err)
	}

	summaryData.CategoryData = categoryData

	// 2. Fetch trend data
	scan, err := s.GetScanByID(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan to retrieve host_id: %w", err)
	}
	if scan == nil {
		return nil, fmt.Errorf("scan not found with id: %s", scanID)
	}

	timePeriods, err := s.GetHostVulnerabilityTrends(scan.HostID, timePeriodFilter, severityFilters)
	if err != nil {
		return nil, fmt.Errorf("failed to get host vulnerabilty trends: %w", err)
	}

	var vulnerabilityTrends domain.ServiceVulnerabilityTrends
	vulnerabilityTrends.TimePeriods = timePeriods

	var totalVulnCountForAvg, periodCountForAvg float64
	for _, periodData := range timePeriods {
		if periodData.VulnerabilityCount != nil {
			totalVulnCountForAvg += float64(*periodData.VulnerabilityCount)
			periodCountForAvg++
		}
	}
	if periodCountForAvg > 0 {
		vulnerabilityTrends.AverageVulnerabilityCount = totalVulnCountForAvg / periodCountForAvg
	} else {
		vulnerabilityTrends.AverageVulnerabilityCount = 0.0
	}
	summaryData.VulnerabilityTrends = vulnerabilityTrends

	return &summaryData, nil
}

func (s *PostgreSQLStore) buildSeverityWhereClause(severityFilters []string, queryParams []any) (string, []any) {
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

func (s *PostgreSQLStore) GetReportsByTenantID(tenantID string) ([]*domain.ReportItem, error) {
	query := `
  SELECT
    s.id AS scan_id,
    h.domain AS host_name,
    h.ip AS ip,
    s.started_at as scan_date,
    (SELECT COUNT(sv.id) FROM scan_vulnerabilities sv WHERE sv.scan_id = s.id) AS total_severities,
    CASE
      WHEN NOT EXISTS (
        SELECT 1
        FROM scan_vulnerabilities sv
        WHERE sv.scan_id = s.id
          AND sv.analyst_comment IS NOT NULL
      ) THEN 'PENDING' -- CommentStatusPending: No commens on any vulnerability
      WHEN EXISTS (
        SELECT 1
        FROM scan_vulnerabilities sv
        WHERE sv.scan_id = s.id
          AND sv.analyst_comment IS NOT NULL
          AND sv.severity = 'Critical'
      ) THEN 'CRITICAL' -- CommentStatusCritical: Comment on at least one Critical vulnerability
      ELSE 'NEW COMMENT' -- CommentStatusNewComment: At least one comment, but no Critical Severity Comments
    END AS comment_status
  FROM scans s
  INNER JOIN hosts h ON s.host_id = h.id
  WHERE s.tenant_id = $1 AND s.status = 'Completed'
  ORDER BY scan_date DESC
  `

	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No rows were found
		}
		return nil, fmt.Errorf("failed to fetch reports: %w", err)
	}
	defer rows.Close()

	reportItems := []*domain.ReportItem{}
	for rows.Next() {
		var reportItem domain.ReportItem
		var commentStatusString string
		err := rows.Scan(
			&reportItem.ScanID,
			&reportItem.HostName,
			&reportItem.IP,
			&reportItem.ScanDate,
			&reportItem.TotalSeverities,
			&commentStatusString,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan into ReportItem: %w", err)
		}

		commentStatusEnum, err := domain.ParseCommentStatus(commentStatusString)
		if err != nil {
			return nil, fmt.Errorf("failed to parse comment status string: %w", err)
		}
		reportItem.CommentStatus = commentStatusEnum

		reportItems = append(reportItems, &reportItem)
	}

	return reportItems, nil
}

func (s *PostgreSQLStore) GetLatestScanByHostID(hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
	query := `
    SELECT
      id,
      tenant_id,
      operator_id,
      host_id,
      started_at,
      created_at,
      updated_at,
      ended_at,
      status,
      protection_score
    FROM
      scans
    WHERE
      host_id = $1
      AND started_at >= COALESCE($2, '1900-01-01'::DATE)
      AND started_at <= COALESCE($3, NOW())
    ORDER BY
      started_at DESC
    LIMIT 1;
  `

	var scan domain.Scan
	row := s.db.QueryRow(query, hostID, fromDate, toDate)
	if err := scanIntoScan(row, &scan); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan into scan: %w", err)
	}

	return &scan, nil
}

func (s *PostgreSQLStore) GetScanBeforeLatestByHostID(hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
	query := `
    SELECT
      id,
      tenant_id,
      operator_id,
      host_id,
      started_at,
      created_at,
      updated_at,
      ended_at,
      status,
      protection_score
    FROM
      scans
    WHERE
      host_id = $1
      AND started_at >= COALESCE($2, '1900-01-01'::DATE)
      AND started_at <= COALESCE($3, NOW())
    ORDER BY
      started_at DESC
    LIMIT 1
    OFFSET 1;
  `

	var scan domain.Scan
	row := s.db.QueryRow(query, hostID, fromDate, toDate)
	if err := scanIntoScan(row, &scan); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan into scan: %w", err)
	}

	return &scan, nil
}

func (s *PostgreSQLStore) GetOldestScanByHostID(hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
	query := `
    SELECT
      id,
      tenant_id,
      operator_id,
      host_id,
      started_at,
      created_at,
      updated_at,
      ended_at,
      status,
      protection_score
    FROM
      scans
    WHERE
      host_id = $1
      AND started_at >= COALESCE($2, '1900-01-01'::DATE)
      AND started_at <= COALESCE($3, NOW())
    ORDER BY
      started_at ASC
    LIMIT 1;
  `

	var scan domain.Scan
	row := s.db.QueryRow(query, hostID, fromDate, toDate)
	if err := scanIntoScan(row, &scan); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan into scan: %w", err)
	}

	return &scan, nil
}

func scanIntoScan(row *sql.Row, scan *domain.Scan) error {
	if err := row.Scan(
		&scan.ID,
		&scan.TenantID,
		&scan.OperatorID,
		&scan.HostID,
		&scan.StartedAt,
		&scan.CreatedAt,
		&scan.UpdatedAt,
		&scan.EndedAt,
		&scan.Status,
		&scan.ProtectionScore,
	); err != nil {
		return fmt.Errorf("error scanning row: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetSeverityCounts(scanID uuid.UUID) (*tools.SeverityCounts, error) {
	query := `
    SELECT
      COALESCE(SUM(CASE WHEN sv.base_severity = 'Unknown' THEN 1 ELSE 0 END), 0) AS unknown_vulnerabilities,
      COALESCE(SUM(CASE WHEN sv.base_severity = 'None' THEN 1 ELSE 0 END), 0) AS none_vulnerabilities,
      COALESCE(SUM(CASE WHEN sv.base_severity = 'Low' THEN 1 ELSE 0 END), 0) AS low_vulnerabilities,
      COALESCE(SUM(CASE WHEN sv.base_severity = 'Medium' THEN 1 ELSE 0 END), 0) as medium_vulnerabilities,
      COALESCE(SUM(CASE WHEN sv.base_severity = 'High' THEN 1 ELSE 0 END), 0) as high_vulnerabilities,
      COALESCE(SUM(CASE WHEN sv.base_severity = 'Critical' THEN 1 ELSE 0 END), 0) AS critical_vulnerabilities
    FROM
      scans
    LEFT JOIN
      scan_vulnerabilities sv ON scans.id = sv.scan_id
    WHERE scans.id = $1
  `

	var severityCounts tools.SeverityCounts

	err := s.db.QueryRow(query, scanID).Scan(
		&severityCounts.Unknown,
		&severityCounts.None,
		&severityCounts.Low,
		&severityCounts.Medium,
		&severityCounts.High,
		&severityCounts.Critical,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Scan was not found
			return nil, fmt.Errorf("scan not found: %s: %w", scanID.String(), err)
		}
		return nil, fmt.Errorf("failed to run query: %w", err)
	}

	return &severityCounts, nil
}

func (s *PostgreSQLStore) CreateScanScheduling(scanID uuid.UUID, cronExpression string, isRepeated bool, periodName string, periodQuantity int, scheduledDate time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	if isRepeated {
		query := `
		INSERT INTO scan_scheduling (
		scan_id, period_name,period_quantity, enabled, has_period, cron, scheduled_date, created_at, updated_at
		)
		values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

		if _, err := tx.Exec(query, scanID, periodName, periodQuantity, true, isRepeated, cronExpression, scheduledDate, time.Now().UTC(), time.Now().UTC()); err != nil {
			return fmt.Errorf("failed to insert scan scheduling: %w", err)
		}
	} else {
		query := `
		INSERT INTO scan_scheduling (
		scan_id, enabled, has_period, cron,scheduled_date, created_at, updated_at
		)
		values ($1, $2, $3, $4, $5, $6, $7)`

		if _, err := tx.Exec(query, scanID, true, isRepeated, cronExpression, scheduledDate, time.Now().UTC(), time.Now().UTC()); err != nil {
			return fmt.Errorf("failed to insert scan scheduling: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) ScanScheduleDisableJob(scanScheduleID int, withDelete bool) error {
	query := `SELECT unregister_cron( $1, $2 )`
	var result int
	err := s.db.QueryRow(query, scanScheduleID, withDelete).Scan(&result)
	if err != nil || result == 0 {
		return fmt.Errorf("failed to unregister job: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) UpdateScanScheduling(scanID uuid.UUID, scanScheduleID int) error {
	query := `UPDATE scan_scheduling SET scan_id=$1, updated_at=now() WHERE id=$2`
	_, err := s.db.Exec(query, scanID, scanScheduleID)
	if err != nil {
		return fmt.Errorf("failed to update scan scheduling: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetRapporteursAndHostAliasByScanID(scanID uuid.UUID) ([]*domain.Rapporteur, string, error) {
	query := `SELECT H.rapporteurs, H.alias FROM scans S INNER JOIN  hosts H ON H.id = S.host_id WHERE S.id=$1 `
	var rapporteursBytes []byte
	var rapporteurs []*domain.Rapporteur
	var name string
	err := s.db.QueryRow(query, scanID).Scan(&rapporteursBytes, &name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.Debug("No rapporteurs found for scan_id: %s", scanID.String(),
				slog.String("scan_id", scanID.String()),
			)
			return nil, "", customerrors.ErrHostNotFound
		}
		return nil, "", fmt.Errorf("failed to run query: %w", err)
	}
	if err := json.Unmarshal(rapporteursBytes, &rapporteurs); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal rapporteurs: %w", err)
	}
	return rapporteurs, name, nil
}

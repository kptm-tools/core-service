package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
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
		return nil, fmt.Errorf("failed to insert scan: %w", err)
	}

	return &insertedScan, nil
}

func (s *PostgreSQLStore) InsertVulnerabilityResult(sr *domain.ScanResult) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()

	if sr.Result.Tool != enums.ToolNmap {
		return fmt.Errorf("scan result tool is invalid: %s", sr.Result.Tool)
	}

	scan, err := s.GetScanByID(sr.ScanID)
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

	// 3. Store OS (if OS data is present in scanResult)
	// If not present, will just store empty values
	operatingSystemID, err := s.CreateOS(tx, scan.HostID, scan.ID, nr.MostLikelyOS)
	if err != nil {
		return fmt.Errorf("failed to store OS data: %w", err)
	}

	// 3.1 Store OS vulners (if present)
	for _, vuln := range nr.MostLikelyOS.Vulnerabilities {
		err := s.CreateOSVulnerability(tx, scan.ID, scan.HostID, operatingSystemID, vuln)
		if err != nil {
			return fmt.Errorf("failed to create OS vulnerability: %w", err)
		}
	}

	// 4. Loop through detected services (PortData)
	for _, portData := range nr.ScannedPorts {
		// 4.1 Store detected Service
		serviceID, err := s.CreateService(tx, scan.HostID, scan.ID, portData)
		if err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}
		// 4.2 Store that Service's vulners
		for _, vuln := range portData.Vulnerabilities {
			err := s.CreateServiceVulnerability(tx, scan.ID, scan.HostID, serviceID, vuln)
			if err != nil {
				return fmt.Errorf("failed to create Service vulnerabiliy: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
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

func (s *PostgreSQLStore) GetScans(tenantID string) ([]*domain.ScanSummary, error) {
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
   WHERE S.tenant_id = $1
   ORDER BY S.started_at DESC`

	rows, err := s.db.Query(query, tenantID)
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

func (s *PostgreSQLStore) GetListOfScanResults(tenantID string) ([]*domain.ScanResult, error) {
	query := `SELECT S.id, SR.tool, result from scan_results SR
	INNER JOIN  (select * from scans where tenant_id=$1) S on SR.scan_id = S.id`
	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch scans: %w", err)
	}
	defer rows.Close()
	scansResults := []*domain.ScanResult{}
	for rows.Next() {
		scanRes := &domain.ScanResult{}
		err := scanIntoScanResult(rows, scanRes)
		if err != nil {
			return nil, fmt.Errorf("failed to scan result: %w", err)
		}
		scansResults = append(scansResults, scanRes)
	}
	return scansResults, nil
}

func scanIntoScanResult(rows *sql.Rows, scanRes *domain.ScanResult) error {
	var result []byte
	if err := rows.Scan(&scanRes.ScanID, &scanRes.ToolName, &result); err != nil {
		return fmt.Errorf("failed to scan host: %w", err)
	}
	if err := json.Unmarshal(result, &scanRes.Result); err != nil {
		log.Println("no results yet")
		// return fmt.Errorf("failed to unmarshal result of scan_results: %w", err)
	}
	return nil
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
        MAX(sv.cvss) AS max_cvss,
        sv.severity AS vuln_severity
      FROM
        scan_vulnerabilities sv
      WHERE
        sv.scan_id = $1
      GROUP BY
        sv.type,
        vuln_severity
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
          vuln_severity
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
	var severityPerType map[string]string

	if insights.TotalVulnerabilities > 0 {
		if err := json.Unmarshal(severityPerTypeJSON, &severityPerType); err != nil {
			return nil, fmt.Errorf("failed to unmarshal severity_per_type JSON: %w", err)
		}
	}

	// Map max cvss values into enums.Severity
	mapSeverities := func(a map[string]string, f func(string) int) map[string]int {
		n := make(map[string]int, len(a))
		for k, v := range a {
			n[k] = f(v)
		}
		return n
	}

	insights.SeverityPerType = mapSeverities(severityPerType, func(s string) int {
		return enums.StringToSeverityType(s).Int()
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
	timePeriodFilter string,
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
	// This query is kind of complicated, but what it does is fill out time_periods and labels,
	// even when there is no data for said time_period. E.g: we only have data
	// for February, but we want to have the counts for other months to be 0 too.
	baseTrendQuery := `
  WITH TimePeriods as (
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
        END AS ordering_period
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
  VulnerabilityCounts AS (
  SELECT
          CASE
              WHEN $2 = 'Month' THEN TO_CHAR(sv.created_at, 'FMMonth')
              WHEN $2 = 'Quarter' THEN 'Q' || TO_CHAR(sv.created_at, 'Q')
              WHEN $2 = 'Semester' THEN 'Semester ' || CASE WHEN TO_CHAR(sv.created_at, 'MM')::integer <= 6 THEN '1' ELSE '2' END
              ELSE 'Unknown Period'
          END AS time_period_label,
          COUNT(sv.id) AS vulnerability_count
      FROM scan_vulnerabilities sv
      WHERE sv.scan_id = $1
        AND EXTRACT(YEAR FROM sv.created_at) = EXTRACT(YEAR FROM CURRENT_DATE)
          -- Severity Filter Dynamic Condition goes here
          %s
      GROUP BY time_period_label
  )
  SELECT 
    tp.time_period_label AS time_period,
    COALESCE(vc.vulnerability_count, 0) AS vulnerability_count
  FROM TimePeriods tp
  LEFT JOIN VulnerabilityCounts vc ON tp.time_period_label = vc.time_period_label
  ORDER BY tp.ordering_period;
`

	trendQueryParams := []any{scanID, timePeriodFilter}
	trendSeverityWhereClause, trendQueryParams := s.buildSeverityWhereClause(severityFilters, trendQueryParams)
	formattedTrendQuery := fmt.Sprintf(baseTrendQuery, trendSeverityWhereClause)
	slog.Debug("Executing Summary Query",
		slog.Any("query_params", trendQueryParams))

	trendsRows, err := s.db.Query(formattedTrendQuery, trendQueryParams...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerability trends: %w", err)
	}
	defer trendsRows.Close()

	var vulnerabilityTrends domain.ServiceVulnerabilityTrends
	var timePeriods []domain.ServiceTimePeriod
	var totalVulnCountForAvg, periodCountForAvg float64
	for trendsRows.Next() {
		var timePeriodData domain.ServiceTimePeriod
		if err := trendsRows.Scan(&timePeriodData.TimePeriod, &timePeriodData.VulnerabilityCount); err != nil {
			return nil, fmt.Errorf("failed to scan into time period: %w", err)
		}
		timePeriods = append(timePeriods, timePeriodData)
		totalVulnCountForAvg += float64(timePeriodData.VulnerabilityCount)
		periodCountForAvg++
	}
	if err := trendsRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate trend rows: %w", err)
	}

	vulnerabilityTrends.TimePeriods = timePeriods
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

func (s *PostgreSQLStore) GetLatestScanByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error) {
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
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to scan into scan: %w", err)
	}

	return &scan, nil
}

func (s *PostgreSQLStore) GetOldestScanByHostID(hostID int, fromDate, toDate *time.Time) (*domain.Scan, error) {
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

func (s *PostgreSQLStore) CreateScanScheduling(scanID uuid.UUID, scheduledAt string, isRepeated bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback()
	fixedYear, cron, errParsing := obtainYearCron(scheduledAt)
	if errParsing != nil {
		return errParsing
	}
	query := `
    INSERT INTO scan_scheduling (
    scan_id, fixed_year, enabled, has_period, cron, created_at, updated_at
    )
    values ($1, $2, $3, $4, $5, $6, $7)`

	if _, err := tx.Exec(query, scanID, fixedYear, true, isRepeated, cron, time.Now().UTC(), time.Now().UTC()); err != nil {
		return fmt.Errorf("failed to insert scan scheduling: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func obtainYearCron(scheduledAt string) (string, string, error) {

	dataCron := strings.Split(scheduledAt, "-")
	if len(dataCron) == 0 {
		return "", "", fmt.Errorf("failed to parse cron expression: %s", scheduledAt)
	}
	var fixedYear, cron string
	var re = regexp.MustCompile(`^[0-9]+$`)
	if len(dataCron[0]) == 4 && re.MatchString(dataCron[0]) && len(dataCron) == 6 {
		fixedYear = dataCron[0]
		cron = fmt.Sprintf("%s %s %s %s %s", dataCron[1], dataCron[2], dataCron[3], dataCron[4], dataCron[5])
	} else if len(dataCron) == 5 {
		cron = fmt.Sprintf("%s %s %s %s %s", dataCron[0], dataCron[1], dataCron[2], dataCron[3], dataCron[4])
	} else {
		return "", "", fmt.Errorf("failed to parse cron expression: %s", scheduledAt)
	}
	return fixedYear, cron, nil
}

package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
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

func (s *PostgreSQLStore) CreateScans(sc *domain.Scan, hostIDs []int) ([]*domain.Scan, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction %w", err)
	}
	if len(hostIDs) == 0 {
		return nil, fmt.Errorf("failed because no hostIDs were provided")
	}
	defer tx.Rollback()
	scans := []*domain.Scan{}
	query := `
    INSERT INTO scans (id, tenant_id, operator_id, host_id, status, started_at)
                values ($1, $2, $3, $4, $5, $6)
    RETURNING id, tenant_id, operator_id, host_id, status, started_at`

	for _, hostID := range hostIDs {
		row := tx.QueryRow(query, sc.ID, sc.TenantID, sc.OperatorID, hostID, sc.Status, sc.StartedAt)
		newScan := &domain.Scan{}
		if err := scanIntoScan(row, newScan); err != nil {
			return nil, fmt.Errorf("failed to insert scan: %w", err)
		}
		scans = append(scans, newScan)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return scans, nil
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

	var nr results.NmapResult
	resultBytes, err := json.Marshal(sr.Result.Result)
	if err != nil {
		return fmt.Errorf("failed to marshal nmap result: %w", err)
	}
	err = json.Unmarshal(resultBytes, &nr)
	if err != nil {
		return fmt.Errorf("failed to unmarshal nmap result: %w", err)
	}

	// Get all vulnerabilities and insert each one to our DB
	for _, port := range nr.ScannedPorts {
		for _, vuln := range port.Vulnerabilities {
			if err := s.InsertScanVulnerability(tx, scan.ID, scan.HostID, sr.Result.Tool, vuln, port); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *PostgreSQLStore) InsertScanVulnerability(
	tx *sql.Tx,
	scanID uuid.UUID,
	hostID int,
	toolName enums.ToolName,
	vuln results.Vulnerability,
	port results.PortData,
) error {
	query := `
    INSERT INTO scan_vulnerabilities (
      vulnerability_id, scan_id, host_id, tool, type, cvss, vuln_references, exploitable,
      port, protocol, service_name, service_version, port_state
    )
    values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`

	referencesBytes, err := json.Marshal(vuln.References)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability references: %w", err)
	}

	if _, err := tx.Exec(query,
		vuln.ID, scanID, hostID, string(toolName), vuln.Type, vuln.CVSS, referencesBytes, vuln.Exploitable,
		port.ID, port.Protocol, port.Service.Name, port.Service.Version, port.State,
	); err != nil {
		return fmt.Errorf("failed to insert vulnerability: %w", err)
	}

	return nil
}

func scanIntoScan(row *sql.Row, scan *domain.Scan) error {
	if err := row.Scan(&scan.ID, &scan.TenantID, &scan.OperatorID, &scan.HostID, &scan.Status, &scan.StartedAt); err != nil {
		return fmt.Errorf("error scanning row: %w", err)
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
      SUM(CASE WHEN V.cvss < 4.0 THEN 1 ELSE 0 END) AS low,
      SUM(CASE WHEN V.cvss >= 4.0 AND V.cvss < 7.0 THEN 1 ELSE 0 END) as medium,
      SUM(CASE WHEN V.cvss >= 7.0 AND V.cvss < 9.0 THEN 1 ELSE 0 END) as high,
      SUM(CASE WHEN V.cvss >= 9.0 THEN 1 ELSE 0 END) AS critical
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
		//return fmt.Errorf("failed to unmarshal result of scan_results: %w", err)
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
      SUM(CASE WHEN sv.cvss < 4.0 THEN 1 ELSE 0 END) AS low_vulnerabilities,
      SUM(CASE WHEN sv.cvss >= 4.0 AND sv.cvss < 7.0 THEN 1 ELSE 0 END) as medium_vulnerabilities,
      SUM(CASE WHEN sv.cvss >= 7.0 AND sv.cvss < 9.0 THEN 1 ELSE 0 END) as high_vulnerabilities,
      SUM(CASE WHEN sv.cvss >= 9.0 THEN 1 ELSE 0 END) AS critical_vulnerabilities,
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
	mapSeverities := func(a map[string]float64, f func(float64) int) map[string]int {
		n := make(map[string]int, len(a))
		for k, v := range a {
			n[k] = f(v)
		}
		return n
	}

	insights.SeverityPerType = mapSeverities(severityPerType, results.MapCVSS)

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
func GetToolResults[T results.IToolResult](s *PostgreSQLStore, scanID uuid.UUID) (T, error) {
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

func (s *PostgreSQLStore) GetProtectionScore(scanID uuid.UUID) (float64, error) {
	const (
		maxEmails      = 50
		maxSubdomains  = 100
		openPortsLimit = 50
		vulnLimit      = 50
	)

	var emailCount, subdomainCount, dnsRecordCount int
	var whoisSuccessful bool
	var vulnResults []results.Vulnerability
	var osDetectionPenalty float64

	// 1. Fetch harvester results
	harvesterResult, err := GetToolResults[*results.HarvesterResult](s, scanID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch harvester results: %w", err)
	}

	// Fetch whois results
	whoisResult, err := GetToolResults[*results.WhoIsResult](s, scanID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch whois results: %w", err)
	}

	// Fetch dnslookup results
	dnsLookupResult, err := GetToolResults[*results.DNSLookupResult](s, scanID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch dnslookup results: %w", err)
	}

	// Fetch nmap results
	nmapResult, err := GetToolResults[*results.NmapResult](s, scanID)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch nmap results: %w", err)
	}

	// Extract relevant data
	emailCount = len(harvesterResult.Emails)
	subdomainCount = len(harvesterResult.Subdomains)
	dnsRecordCount = len(dnsLookupResult.DNSRecords)
	whoisSuccessful = whoisResult.Error == ""
	openPorts := len(nmapResult.GetOpenPorts())

	// Extract vulnerability data
	vulners := nmapResult.GetAllVulnerabilites()
	slog.Debug("Got vulnerabilities from scan",
		slog.String("scan_id", scanID.String()),
		slog.Any("vulnerabilities", vulners))
	vulnResults = append(vulnResults, vulners...)
	vulnCounts := results.GetSeverityCounts(vulnResults)

	// Calculate penalties
	if nmapResult.MostLikelyOS != "" {
		osDetectionPenalty = 10.0
	}

	// Calculate protection sub-scores
	emailScore := normalizeScore(float64(emailCount), maxEmails)
	subdomainScore := normalizeScore(float64(subdomainCount), maxSubdomains)
	whoisScore := 20 * boolToFloat(whoisSuccessful)
	dnsScore := normalizeScore(float64(dnsRecordCount)*10, 1)
	openPortsScore := normalizeScore(float64(openPorts), openPortsLimit)

	// Vulnerability score (severity-weighted)
	vulnScore := normalizeScore(float64(vulnCounts.Low*1+vulnCounts.Medium*3+vulnCounts.High*7+vulnCounts.Critical*15), vulnLimit)

	slog.Info("Protection Score Calculation Data",
		slog.Int("email_count", emailCount),
		slog.Int("subdomain_count", subdomainCount),
		slog.Int("dns_record_count", dnsRecordCount),
		slog.Bool("whois_successful", whoisSuccessful),
		slog.Int("open_ports", openPorts),
		slog.Int("vuln_low", vulnCounts.Low),
		slog.Int("vuln_medium", vulnCounts.Medium),
		slog.Int("vuln_high", vulnCounts.High),
		slog.Int("vuln_critical", vulnCounts.Critical),
	)

	slog.Debug("Individual Component Scores",
		slog.Float64("email_score", emailScore),
		slog.Float64("subdomain_score", subdomainScore),
		slog.Float64("whois_score", whoisScore),
		slog.Float64("dns_score", dnsScore),
		slog.Float64("vuln_score", vulnScore),
		slog.Float64("open_ports_score", openPortsScore),
		slog.Float64("os_detection_penalty", osDetectionPenalty),
	)

	// Calculate final protection score (higher sub-scores decrease protection)
	finalScore := 100 - (0.2*emailScore +
		0.2*subdomainScore +
		0.1*whoisScore +
		0.1*dnsScore +
		0.4*vulnScore +
		0.2*openPortsScore +
		osDetectionPenalty)

	// Normalize between [0,1]
	finalScore = math.Max(0, math.Min(finalScore/100, 1))

	slog.Info("Final Protection Score",
		slog.String("scan_id", scanID.String()),
		slog.Float64("final_score", finalScore))

	return finalScore, nil
}

// normalizeScore is a utility function to normalize a score
// (higher values indicate higher risk)
func normalizeScore(value, max float64) float64 {
	return 100 * (math.Min(value/max, 1))
}

func boolToFloat(value bool) float64 {
	if value {
		return 1.0
	}
	return 0.0
}

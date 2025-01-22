package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/results"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) CreateScanTable() error {
	query := `create table if not exists scans (
      id UUID PRIMARY KEY,
      tenant_id UUID NOT NULL,
      operator_id UUID NOT NULL,
      host_id INT REFERENCES hosts(id) ON DELETE CASCADE,
      status VARCHAR(50) NOT NULL, -- e.g., 'pending', 'in_progress', 'completed', 'failed'
      started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ended_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateScanVulnerabilityTable() error {
	query := `create table if not exists vulnerability (
      id SERIAL PRIMARY KEY,
      scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
      host_id INT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
      tool_id INT NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
      type       VARCHAR(50),
	  cvss       DECIMAL(3,2),
	  reference  JSONB,
	  exploitable BOOLEAN
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateScanResultsTable() error {
	query := `create table if not exists scan_results (
      id SERIAL PRIMARY KEY,
      scan_id UUID REFERENCES scans (id) ON DELETE CASCADE,
      tool_id INT REFERENCES tools(id) ON DELETE CASCADE,
      status  VARCHAR(50) NOT NULL,
      result JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateToolTable() error {
	query := `create table if not exists tools (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL, -- Tool name
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type INT NOT NULL
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) InsertTools() error {
	// Check if the table is already populated
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM tools").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check tools count: %w", err)
	}

	if count > 0 {
		slog.Info("Tools table already populated, skipping insertion.")
		return nil
	}

	toolsData := s.getDefaultTools()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction %w", err)
	}
	defer tx.Rollback()

	query := `INSERT INTO tools (name, description, created_at, type) 
 	VALUES ($1, $2, $3, $4)`

	for _, data := range toolsData {
		if _, err := tx.Exec(query, data.Name, data.Description, data.CreatedAt, data.Type); err != nil {
			return fmt.Errorf("failed to insert tool: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	slog.Info("Tools table populated successfully.")
	return nil
}

func (s *PostgreSQLStore) getDefaultTools() []domain.Tool {
	toolsData := []domain.Tool{
		{
			Name:        string(enums.ToolDNSLookup),
			Description: "This kali tool looks up the DNS server IP address",
			CreatedAt:   time.Now(),
			Type:        0,
		},
		{
			Name:        string(enums.ToolWhoIs),
			Description: "This kali tool uses WhoIs to obtain ownership info and IP address history",
			CreatedAt:   time.Now(),
			Type:        0,
		},
		{
			Name:        string(enums.ToolHarvester),
			Description: "This kali tool uses harvester to obtain subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public source",
			CreatedAt:   time.Now(),
			Type:        0,
		},
		{
			Name:        string(enums.ToolNmap),
			Description: "This kali tool uses nmap to obtain vulnerabilities",
			CreatedAt:   time.Now(),
			Type:        1,
		},
	}
	return toolsData
}

func (s *PostgreSQLStore) ClearScanTable() error {
	query := `TRUNCATE TABLE scans RESTART IDENTITY CASCADE`

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
    INSERT INTO scans (id, tenant_id, operator_id, host_id, status, started_at, ended_at)
                values ($1, $2, $3, $4, $5, $6, $7)
    RETURNING id, tenant_id, operator_id, host_id, status, started_at, ended_at`

	for _, hostID := range hostIDs {
		row := tx.QueryRow(query, sc.ID, sc.TenantID, sc.OperatorID, hostID, sc.Status, sc.StartedAt, sc.EndedAt)
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

func (s *PostgreSQLStore) CreateVulnerabilityResult(sr *domain.ScanResult) error {
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

	// 1. Save the result to scan_results
	if err := s.InsertScanResult(tx, sr); err != nil {
		return fmt.Errorf("failed to insert to scan_results: %w", err)
	}

	// 2. Parse vulnerabilities and store them to vulnerabilities
	if sr.Result.Err != nil {
		slog.Warn("Vulnerability scan has errors, skipping vulnerability insertion")
		return nil
	}

	nmapRes, ok := sr.Result.Result.(results.NmapResult)
	if !ok {
		return fmt.Errorf("scan result type is invalid")
	}

	// Get all vulnerabilities and insert each one to our DB
	vulners := nmapRes.GetAllVulnerabilites()
	for _, vuln := range vulners {
		if err := s.InsertScanVulnerability(tx, scan.ID, scan.HostID, sr.ToolID, vuln); err != nil {
			return fmt.Errorf("failed to insert Vulnerability: %w", err)
		}
	}

	return nil
}

func (s *PostgreSQLStore) InsertScanVulnerability(tx *sql.Tx, scanID uuid.UUID, hostID int, toolID int, vuln results.Vulnerability) error {
	query := `
    INSERT INTO vulnerability (scan_id, host_id, type, cvss, references, exploitable)
    values ($1, $2, $3,$4,$5,$6)`

	referencesBytes, err := json.Marshal(vuln.References)
	if err != nil {
		return fmt.Errorf("failed to marshal vulnerability references: %w", err)
	}
	if _, err := tx.Exec(query, scanID, hostID, toolID, vuln.Type, vuln.CVSS, referencesBytes, vuln.Exploitable); err != nil {
		return fmt.Errorf("failed to insert vulnerability: %w", err)
	}
	return nil
}

func scanIntoScan(row *sql.Row, scan *domain.Scan) error {
	if err := row.Scan(&scan.ID, &scan.TenantID, &scan.OperatorID, &scan.HostID, &scan.Status, &scan.StartedAt, &scan.EndedAt); err != nil {
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
    LEFT JOIN vulnerability V ON S.id = V.scan_id
    WHERE S.tenant_id = $1
    GROUP BY S.id
  )
    SELECT
      S.id AS scan_id,
      S.started_at AS scan_date,
      H.alias AS host,
      EXTRACT(epoch from COALESCE(S.ended_at, NOW()) - S.started_at) as duration,
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
	query := `SELECT S.id, SR.tool_id, result from scan_results SR
	INNER JOIN  (select * from scans where tenant_id=$1) S on SR.scan_id = S.id
	    INNER JOIN (SELECT * FROM tools WHERE type= 1) T ON SR.tool_id= T.id`
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
	if err := rows.Scan(&scanRes.ScanID, &scanRes.ToolID, &result); err != nil {
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
    INSERT INTO scan_results (scan_id, tool_id, result, created_at)
    values ($1, $2, $3, $4)`

	toolID, err := s.GetToolIDByName(string(sr.Result.Tool))
	if err != nil {
		return fmt.Errorf("failed to fetch tool by name: %w", err)
	}

	resultBytes, err := json.Marshal(sr.Result)
	if err != nil {
		return fmt.Errorf("error marshalling scan result: %w", err)
	}

	if _, err := tx.Exec(query, sr.ScanID, toolID, resultBytes, sr.CreatedAt); err != nil {
		return fmt.Errorf("failed to insert scan_results: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetTools() ([]string, error) {
	query := `
    SELECT id FROM tools
  	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer rows.Close()
	IDs := []string{}
	for rows.Next() {
		var ID string
		if err := rows.Scan(&ID); err != nil {
			log.Fatal(err)
		}
		IDs = append(IDs, ID)
	}

	return IDs, nil
}

func (s *PostgreSQLStore) GetToolIDByName(toolName string) (int, error) {
	query := `
    SELECT id
    FROM tools
    WHERE name = $1
  `
	var id int
	err := s.db.QueryRow(query, toolName).Scan(&id)
	return id, err
}

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
	cmmnRes "github.com/kptm-tools/common/common/results"
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
		errInsertScanResultInitial := s.InsertScanHostResult(tx, newScan)
		if errInsertScanResultInitial != nil {
			return nil, errInsertScanResultInitial
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	return scans, nil
}

func (s *PostgreSQLStore) InsertScanVulnerability(tx *sql.Tx, sc *domain.Scan, hostIDs []*string) error {
	query := `
    INSERT INTO vulnerability (scan_id, host_id, type, cvss, references, exploitable)
    values ($1, $2, $3,$4,$5,$6)`

	if len(hostIDs) == 0 {
		return fmt.Errorf("failed because no hostIDs were provided")
	}

	for _, hostID := range hostIDs {
		if _, err := tx.Exec(query, sc.ID, hostID); err != nil {
			return fmt.Errorf("failed to insert vulnerability: %w", err)
		}
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
	)
	if err != nil {
		return nil, fmt.Errorf("error retrieving Scan: %w", err)
	}

	return scanSum, nil
}
func (s *PostgreSQLStore) GetScans(tenantID string) ([]*domain.ScanSummary, error) {
	scanResults, errGetScansResults := s.GetListOfScanResults(tenantID)
	if errGetScansResults != nil {
		return nil, errGetScansResults
	}

	query := `
           SELECT S.id,S.started_at, alias, extract(epoch from max(SR.updated_at) - S.started_at) as duration,
           S.status
     FROM  scan_results SR
    INNER JOIN (SELECT * FROM tools WHERE type= 1) T ON SR.tool_id= T.id
  	INNER JOIN  (select * from scans where tenant_id=$1) S on SR.scan_id = S.id
	INNER JOIN hosts H ON S.host_id = H.id
GROUP BY S.id, S.started_at, alias, S.status
  `

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
		countVulnerability, vulnerability := s.GetTotalVulnerabilities(scanSum.ScanID, scanResults)
		scanSum.Vulnerabilities = countVulnerability
		scanSum.Severities = vulnerability
		scans = append(scans, scanSum)
	}

	return scans, nil
}

func (s *PostgreSQLStore) GetTotalVulnerabilities(id uuid.UUID, results []*domain.ScanResult) (int, domain.SeverityCounts) {
	var total int
	var totalSeverity domain.SeverityCounts
	for _, result := range results {
		if result.ScanID == id {
			total = total + result.Result.TotalVulnerabilities()
			dataSeverity := cmmnRes.GetSeverityCounts(result.Result.GetAllVulnerabilites())
			totalSeverity.Low = totalSeverity.Low + dataSeverity.Low
			totalSeverity.Medium = totalSeverity.Medium + dataSeverity.Medium
			totalSeverity.High = totalSeverity.High + dataSeverity.High
			totalSeverity.Critical = totalSeverity.Critical + dataSeverity.Critical
		}
	}
	return total, totalSeverity
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

func (s *PostgreSQLStore) InsertScanHostResult(tx *sql.Tx, sc *domain.Scan) error {
	query := `
    INSERT INTO scan_results (scan_id, tool_id,status, created_at, updated_at)
    values ($1, $2, $3,$4, $5)`

	toolIDs, errTool := s.GetTools()
	if errTool != nil {
		return errTool
	}
	for _, toolID := range toolIDs {
		if _, err := tx.Exec(query, sc.ID, toolID, enums.StatusPending.String(), time.Now().UTC(), time.Now().UTC()); err != nil {
			return fmt.Errorf("failed to insert scan_results: %w", err)
		}
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

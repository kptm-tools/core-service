package storage

import (
	"database/sql"
	"fmt"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
	"log"
	"time"
)

func (s *PostgreSQLStore) CreateScanTable() error {
	query := `create table if not exists scans (
      id SERIAL PRIMARY KEY,
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
      scan_id INT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
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
      scan_id INT REFERENCES scans (id) ON DELETE CASCADE,
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

	return nil
}

func (s *PostgreSQLStore) getDefaultTools() []domain.Tool {
	toolsData := []domain.Tool{
		{
			Name:        string(enums.DNSLookupEventSubject),
			Description: "This kali tool looks up the DNS server IP address",
			CreatedAt:   time.Now(),
			Type:        0,
		},
		{
			Name:        string(enums.WhoIsEventSubject),
			Description: "This kali tool use WhoIs to obtain ownership info and IP address history",
			CreatedAt:   time.Now(),
			Type:        0,
		},
		{
			Name:        string(enums.HarvesterEventSubject),
			Description: "This kali tool use harvester to obtain subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public source",
			CreatedAt:   time.Now(),
			Type:        0,
		},
		{
			Name:        string(enums.NmapEventSubject),
			Description: "This kali tool use nmap to obtain vulnerabilities",
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

func (s *PostgreSQLStore) CreateScans(sc *domain.Scan, hostIDs []*string) ([]*domain.Scan, error) {
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
    INSERT INTO scans (tenant_id, operator_id, host_id, status, started_at, ended_at)
    values ($1, $2, $3,'PENDING', $4, $5)
    RETURNING id, tenant_id, operator_id, status, started_at, ended_at`

	for _, hostID := range hostIDs {
		row := tx.QueryRow(query, sc.TenantID, sc.OperatorID, hostID, sc.StartedAt, sc.EndedAt)
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
	if err := row.Scan(&scan.ID, &scan.TenantID, &scan.OperatorID, &scan.Status, &scan.StartedAt, &scan.EndedAt); err != nil {
		return fmt.Errorf("error scanning row: %w", err)
	}
	return nil
}

func scanIntoScanSum(rows *sql.Rows) (*domain.ScanSummary, error) {
	scanSum := new(domain.ScanSummary)
	err := rows.Scan(
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
           SELECT S.started_at, alias, extract(epoch from max(SR.updated_at) - S.started_at) as duration,
            COUNT(CASE WHEN SR.STATUS = 'PENDING' THEN 1
                WHEN SR.STATUS = 'INPROGRESS' THEN 2
                WHEN SR.STATUS = 'COMPLETED' THEN 3
                WHEN SR.STATUS = 'FAILED' THEN -1
                ELSE 0
                END) as statusNumber,
            COUNT(V.CVSS) as vulnerablities,
     COUNT(CASE WHEN V.CVSS < 4 THEN 1 END) AS Low,
          COUNT(CASE WHEN V.CVSS < 7 THEN 1 END) AS Medium,
               COUNT(CASE WHEN V.CVSS < 9 THEN 1 END) AS High,
                    COUNT(CASE WHEN V.CVSS >= 9 THEN 1 END) AS Critical
     FROM  scan_results SR
    INNER JOIN hosts H ON SR.host_id = H.id
    INNER JOIN (SELECT * FROM tools WHERE type= 1) T ON SR.tool_id= T.id
  	INNER JOIN  (select * from scans where tenant_id=$1) S on SR.scan_id = S.id
              LEFT JOIN vulnerability V ON  SR.host_id = V.host_id and SR.scan_id=V.host_id and SR.tool_id =V.tool_id
     group by SR.scan_id, SR.host_id,S.started_at, alias
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
		scans = append(scans, scanSum)
	}

	return scans, nil
}

func (s *PostgreSQLStore) InsertScanHostResult(tx *sql.Tx, sc *domain.Scan) error {
	query := `
    INSERT INTO scan_results (scan_id, tool_id,status, created_at, updated_at)
    values ($1, $2, $3,$4, $5,$6)`

	toolIDs, errTool := s.GetTools()
	if errTool != nil {
		return errTool
	}
	for _, toolID := range toolIDs {
		if _, err := tx.Exec(query, sc.ID, toolID, "PENDING", time.Now(), time.Now()); err != nil {
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

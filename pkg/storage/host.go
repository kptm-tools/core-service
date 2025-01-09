package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) CreateHostsTable() error {
	query := `create table if not exists hosts (
      id SERIAL PRIMARY KEY,
      tenant_id UUID,
      operator_id UUID,
      domain VARCHAR(2048),
      ip VARCHAR(15),
      alias VARCHAR(2048) UNIQUE NOT NULL,
      rapporteurs JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	queryEnablePgcrypto := `create extension if not exists pgcrypto;`
	_, errPgCrypto := s.db.Query(queryEnablePgcrypto)
	if errPgCrypto != nil {
		return errPgCrypto
	}

	return nil

}

func (s *PostgreSQLStore) CreateCredentialsTable() error {
	query := `create table if not exists credentials (
      id SERIAL PRIMARY KEY,
      host_id integer REFERENCES hosts (id) ON DELETE CASCADE,
      username text  NOT NULL,
      password text  NOT NULL
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil

}

func (s *PostgreSQLStore) ClearHostsTable() error {
	query := `TRUNCATE TABLE hosts RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateHost(t *domain.Host) (*domain.Host, error) {

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction %w", err)
	}
	defer tx.Rollback()

	query := `
    INSERT INTO hosts (tenant_id, operator_id, domain, ip, alias, rapporteurs,  created_at, updated_at)
    values ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING id, tenant_id, operator_id, domain, ip, alias, rapporteurs, created_at, updated_at`

	rapporteursJSONB, err := json.Marshal(t.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rapporteurs: %w", err)
	}

	row := tx.QueryRow(query, t.TenantID, t.OperatorID, t.Domain, t.IP, t.Name, rapporteursJSONB, t.CreatedAt, t.UpdatedAt)
	newHost := &domain.Host{}

	if err := scanIntoHostRow(row, newHost); err != nil {
		return nil, fmt.Errorf("failed to insert host: %w", err)
	}

	if err := s.InsertCredentials(tx, newHost.ID, t.Credentials); err != nil {
		return nil, fmt.Errorf("failed to insert credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Retreive and assign credentials
	newHost.Credentials, err = s.GetCredentials(newHost.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	return newHost, nil
}

func (s *PostgreSQLStore) GetHostsByTenantIDAndUserID(tenantID string, userID string) ([]*domain.Host, error) {

	query := `
    SELECT *
    FROM hosts
    WHERE tenant_id=$1 AND operator_id= $2
  `

	rows, err := s.db.Query(query, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer rows.Close()

	hosts := []*domain.Host{}
	for rows.Next() {
		host := &domain.Host{}
		if err := scanIntoHost(rows, host); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}
		host.Credentials, err = s.GetCredentials(host.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch credentials: %w", err)
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (s *PostgreSQLStore) GetHostByID(ID int) (*domain.Host, error) {

	query := `
    SELECT *
    FROM hosts
    WHERE id=$1
  `

	row := s.db.QueryRow(query, ID)
	host := &domain.Host{}
	var err error

	if err = scanIntoHostRow(row, host); err != nil {
		return nil, fmt.Errorf("failed to fetch host: %w", err)
	}

	credentials, err := s.GetCredentials(ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credentials: %w", err)
	}
	host.Credentials = credentials

	return host, nil
}

func (s *PostgreSQLStore) PatchHostByID(h *domain.Host) (*domain.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
    UPDATE hosts
    SET  rapporteurs=$2, domain=$3, ip=$4, alias=$5
        WHERE id=$1
    RETURNING *
  `
	rapporteursJSONB, err := json.Marshal(h.Rapporteurs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rapporteurs: %w", err)
	}

	row := tx.QueryRow(query, h.ID, rapporteursJSONB, h.Domain, h.IP, h.Name)
	host := &domain.Host{}
	if err := scanIntoHostRow(row, host); err != nil {
		return nil, fmt.Errorf("error fetching host: %w", err)
	}

	if err = s.UpdateCredentials(tx, host.ID, h.Credentials); err != nil {
		return nil, fmt.Errorf("failed to update credentials: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Fetch and assign updated credentials
	credentials, err := s.GetCredentials(host.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated credentials: %w", err)
	}
	host.Credentials = credentials

	return host, nil
}

func (s *PostgreSQLStore) InsertCredentials(tx *sql.Tx, hostID int, credentials []domain.Credential) error {

	query := "INSERT INTO credentials (host_id, username, password) VALUES ($1, $2, pgp_sym_encrypt($3, 'MAMA', 'compress-algo=1, cipher-algo=aes256'))"
	for _, cred := range credentials {
		if _, err := tx.Exec(query, hostID, cred.Username, cred.Password); err != nil {
			return fmt.Errorf("failed to insert credential: %w", err)
		}
	}

	return nil
}

func (s *PostgreSQLStore) GetCredentials(hostID int) ([]domain.Credential, error) {

	query := `
    SELECT id, host_id, username,password
    FROM credentials
    WHERE host_id=$1
  `

	rows, err := s.db.Query(query, hostID)
	if err != nil {
		return nil, fmt.Errorf("error fetching Credentials: %w", err)
	}
	defer rows.Close()

	credentials := []domain.Credential{}
	for rows.Next() {
		credential, err := scanIntoCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan credential: %w", err)
		}
		credentials = append(credentials, *credential)
	}
	return credentials, nil
}

func (s *PostgreSQLStore) UpdateCredentials(tx *sql.Tx, hostID int, credentials []domain.Credential) error {
	// Step 1: Delete all credentials associated with the hostID
	deleteQuery := `DELETE FROM credentials WHERE host_id = $1`
	if _, err := tx.Exec(deleteQuery, hostID); err != nil {
		return fmt.Errorf("failed to delete existing credentials for hostID %d: %w", hostID, err)
	}

	insertQuery := `INSERT INTO credentials (host_id, username, password)
                  VALUES ($1, $2, pgp_sym_encrypt($3, 'MAMA', 'compress-algo=1, cipher-algo=aes256'))`

	for _, cred := range credentials {
		_, err := tx.Exec(insertQuery, hostID, cred.Username, cred.Password)
		if err != nil {
			return fmt.Errorf("failed to insert new credential for hostID %d: %w", hostID, err)
		}
	}
	return nil
}

func (s *PostgreSQLStore) DeleteHostByID(ID int) (bool, error) {

	query := `
    DELETE 
    FROM hosts
    WHERE id=$1
  `
	res, err := s.db.Exec(query, ID)

	switch err {
	case nil:
		count, _ := res.RowsAffected()
		return count == 1, nil
	default:
		return false, err
	}
}

func scanIntoHost(rows *sql.Rows, host *domain.Host) error {
	var rapporteurs []byte
	if err := rows.Scan(&host.ID, &host.TenantID, &host.OperatorID, &host.Domain, &host.IP, &host.Name, &rapporteurs, &host.CreatedAt, &host.UpdatedAt); err != nil {
		return fmt.Errorf("error scanning rows: %w", err)
	}
	// Unmarshal the rapporteurs bytes
	if err := json.Unmarshal(rapporteurs, &host.Rapporteurs); err != nil {
		return fmt.Errorf("error unmarshalling rapporteurs: %w", err)
	}

	return nil
}

func scanIntoHostRow(row *sql.Row, host *domain.Host) error {
	var rapporteurs []byte
	if err := row.Scan(&host.ID, &host.TenantID, &host.OperatorID, &host.Domain, &host.IP, &host.Name, &rapporteurs, &host.CreatedAt, &host.UpdatedAt); err != nil {
		return fmt.Errorf("failed to scan host: %w", err)
	}
	if err := json.Unmarshal(rapporteurs, &host.Rapporteurs); err != nil {
		return fmt.Errorf("failed to unmarshal rapporteurs: %w", err)
	}

	return nil
}
func scanIntoCredential(rows *sql.Rows) (*domain.Credential, error) {

	credential := new(domain.Credential)
	err := rows.Scan(
		&credential.ID,
		&credential.HostID,
		&credential.Username,
		&credential.Password,
	)

	if err != nil {
		return nil, fmt.Errorf("error scanning Credential: %w", err)
	}

	return credential, nil
}

func replaceSQL(old, searchPattern string) string {
	tmpCount := strings.Count(old, searchPattern)
	for m := 1; m <= tmpCount; m++ {
		old = strings.Replace(old, searchPattern, "$"+strconv.Itoa(m), 1)
	}
	return old
}

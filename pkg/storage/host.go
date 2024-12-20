package storage

import (
	"database/sql"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/domain"
	"strconv"
)

func (s *PostgreSQLStore) CreateHostsTable() error {
	query := `create table if not exists hosts (
      id SERIAL PRIMARY KEY,
      tenant_id UUID,
      operator_id UUID,
      domain VARCHAR(2048) UNIQUE NOT NULL,
      ip VARCHAR(15) NOT NULL,
      alias VARCHAR(2048) UNIQUE NOT NULL,
      credentials	JSONB,
      rapporteurs JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

	query := `
    INSERT INTO hosts (tenant_id, operator_id, domain, ip, alias, credentials, rapporteurs,  created_at, updated_at)
    values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING id, tenant_id, operator_id, domain, ip, alias, credentials, rapporteurs, created_at, updated_at`

	rows, err := s.db.Query(query, t.TenantID, t.OperatorID, t.Domain, t.Ip, t.Name, t.Credentials, t.Rapporteurs, t.CreatedAt, t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("error creating Host: `%v`", err)
	}

	for rows.Next() {
		return scanIntoHost(rows)
	}

	return nil, fmt.Errorf("error creating Host")
}

func (s *PostgreSQLStore) GetHostsByTenantIDAndUserID(tenantID string, userID string) ([]*domain.Host, error) {

	query := `
    SELECT *
    FROM hosts
    WHERE tenant_id=$1 and operator_id= $2
  `

	rows, err := s.db.Query(query, tenantID, userID)

	if err != nil {
		return nil, fmt.Errorf("error fetching Hosts: `%+v`", err)
	}

	hosts := []*domain.Host{}

	for rows.Next() {
		host, err := scanIntoHost(rows)

		if err != nil {
			return nil, fmt.Errorf("error scanning into Host: `%+v`", err)
		}
		hosts = append(hosts, host)
	}

	return hosts, nil
}

func (s *PostgreSQLStore) GetHostByID(ID string) (*domain.Host, error) {

	query := `
    SELECT *
    FROM hosts
    WHERE id=$1
  `
	i, _ := strconv.Atoi(ID)
	row := s.db.QueryRow(query, i)
	host := new(domain.Host)
	err := row.Scan(&host.ID,
		&host.TenantID,
		&host.OperatorID,
		&host.Domain,
		&host.Ip,
		&host.Name,
		&host.Credentials,
		&host.Rapporteurs,
		&host.CreatedAt,
		&host.UpdatedAt)

	switch err {
	case sql.ErrNoRows:
		return nil, fmt.Errorf("No rows were returned: `%+v`", err)
	case nil:
		return host, nil
	default:
		return nil, err
	}
}

func (s *PostgreSQLStore) PatchHostByID(ID, domainName, ip, alias string, credential, rapporteur []byte) (*domain.Host, error) {

	query := `
    UPDATE hosts
    SET credentials=$2, rapporteurs=$3, domain=$4, ip=$5, alias=$6
        WHERE id=$1
    RETURNING *
  `
	i, _ := strconv.Atoi(ID)
	row := s.db.QueryRow(query, i, credential, rapporteur, domainName, ip, alias)
	host := new(domain.Host)
	err := row.Scan(&host.ID,
		&host.TenantID,
		&host.OperatorID,
		&host.Domain,
		&host.Ip,
		&host.Name,
		&host.Credentials,
		&host.Rapporteurs,
		&host.CreatedAt,
		&host.UpdatedAt)

	switch err {
	case sql.ErrNoRows:
		return nil, fmt.Errorf("No rows were returned: `%+v`", err)
	case nil:
		return host, nil
	default:
		return nil, err
	}
}

func (s *PostgreSQLStore) DeleteHostByID(ID string) (bool, error) {

	query := `
    DELETE 
    FROM hosts
    WHERE id=$1
  `
	i, _ := strconv.Atoi(ID)
	res, err := s.db.Exec(query, i)

	switch err {
	case nil:
		count, _ := res.RowsAffected()
		return count == 1, nil
	default:
		return false, err
	}
}

func scanIntoHost(rows *sql.Rows) (*domain.Host, error) {

	host := new(domain.Host)

	err := rows.Scan(
		&host.ID,
		&host.TenantID,
		&host.OperatorID,
		&host.Domain,
		&host.Ip,
		&host.Name,
		&host.Credentials,
		&host.Rapporteurs,
		&host.CreatedAt,
		&host.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return host, nil
}

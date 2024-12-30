package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/domain"
	"strconv"
	"strings"
	"time"
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

	query := `
    INSERT INTO hosts (tenant_id, operator_id, domain, ip, alias, rapporteurs,  created_at, updated_at)
    values ($1, $2, $3, $4, $5, $6, $7, $8)
    RETURNING id, tenant_id, operator_id, domain, ip, alias, rapporteurs, created_at, updated_at`
	jsonbRapporteurs, _ := json.Marshal(t.Rapporteurs)
	rows, err := s.db.Query(query, t.TenantID, t.OperatorID, t.Domain, t.IP, t.Name, jsonbRapporteurs, t.CreatedAt, t.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("error creating Host: `%v`", err)
	}

	rows.Next()
	hostObject, errReading := scanIntoHost(rows)

	if errReading != nil {
		return nil, fmt.Errorf("error creating Host: `%v`", errReading)
	}

	sqlStr := "INSERT INTO credentials (host_id, username, password) VALUES "
	vals := []interface{}{}

	for _, row := range t.Credentials {
		sqlStr += "(?, ?, pgp_sym_encrypt(?, 'MAMA', 'compress-algo=1, cipher-algo=aes256')),"
		vals = append(vals, hostObject.ID, row.Username, row.Password)
	}

	//trim the last ,
	sqlStr = strings.TrimSuffix(sqlStr, ",")

	//Replacing ? with $n for postgres
	sqlStr = replaceSQL(sqlStr, "?")

	//prepare the statement
	stmt, errPreparing := s.db.Prepare(sqlStr)

	if errPreparing != nil {
		return nil, fmt.Errorf("error creating credentials: `%v`", err)
	}
	//format all vals at once
	_, errCredential := stmt.Exec(vals...)

	if errCredential != nil {
		return nil, fmt.Errorf("error creating credentials: `%v`", err)
	}
	hostObject.Credentials, _ = s.GetCredentials(hostObject.ID)
	return hostObject, nil
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
		host.Credentials, err = s.GetCredentials(host.ID)
		if err != nil {
			return nil, fmt.Errorf("error scanning into Credential: `%+v`", err)
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

	row, err := s.db.Query(query, i)
	if err != nil {
		return nil, fmt.Errorf("error fetching Hosts: `%+v`", err)
	}
	host, err := s.getResultHost(row)
	if err != nil {
		return nil, fmt.Errorf("error procesing Host from DB: `%+v`", err)
	}
	return host, nil
}

func (s *PostgreSQLStore) getResultHost(row *sql.Rows) (*domain.Host, error) {
	row.Next()
	host, err := scanIntoHost(row)
	if err != nil {
		return nil, fmt.Errorf("error scannig Host: `%+v`", err)
	}
	host.Credentials, err = s.GetCredentials(host.ID)
	if err != nil {
		return nil, fmt.Errorf("error scannig Credentials: `%+v`", err)
	}
	return host, nil
}

func (s *PostgreSQLStore) PatchHostByID(h *domain.Host) (*domain.Host, error) {

	query := `
    UPDATE hosts
    SET  rapporteurs=$2, domain=$3, ip=$4, alias=$5
        WHERE id=$1
    RETURNING *
  `
	jsonbRapporteurs, _ := json.Marshal(h.Rapporteurs)
	i, _ := strconv.Atoi(h.ID)
	rows, err := s.db.Query(query, i, jsonbRapporteurs, h.Domain, h.IP, h.Name)
	if err != nil {
		return nil, fmt.Errorf("error fetching Hosts: `%+v`", err)
	}
	host, err := s.getResultHost(rows)
	if err != nil {
		return nil, fmt.Errorf("error procesing Host from DB: `%+v`", err)
	}

	status, err := s.UpdateCredentials(h.Credentials)
	if err != nil {
		return nil, fmt.Errorf("error updating Credentials: `%+v`", err)
	}
	if status {
		host.Credentials, err = s.GetCredentials(host.ID)
		if err != nil {
			return nil, fmt.Errorf("error fetching Credentials: `%+v`", err)
		}
	}

	return host, nil
}

func (s *PostgreSQLStore) UpdateCredentials(credentialObject []domain.Credential) (bool, error) {
	query := "UPDATE credentials SET username = data.name, password = data.pass FROM ( VALUES "
	args := []interface{}{}
	for i, data := range credentialObject {
		if data.ID != "" {
			query += fmt.Sprintf("($%d, $%d, pgp_sym_encrypt($%d, 'MAMA', 'compress-algo=1, cipher-algo=aes256')),", i*3+1, i*3+2, i*3+3)
			args = append(args, data.ID, data.Username, data.Password)
		}
	}
	query = strings.TrimSuffix(query, ",") + ") AS data(id, name, pass) WHERE credentials.id =  NULLIF(data.id, '')::int;"
	_, err := s.db.Query(query, args...)

	if err != nil {
		return false, fmt.Errorf("error updating Credentials: `%+v`", err)
	}
	return true, nil
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
	cols, _ := rows.Columns()
	columns := make([]interface{}, len(cols))
	columnPointers := make([]interface{}, len(cols))
	for i := range columns {
		columnPointers[i] = &columns[i]
	}

	if err := rows.Scan(columnPointers...); err != nil {
		return nil, err
	}
	for i, colName := range cols {
		val := columnPointers[i].(*interface{})
		var x = *val
		switch colName {
		case "id":
			host.ID = fmt.Sprintf("%v", x)
		case "domain":
			host.Domain = fmt.Sprintf("%v", x)
		case "ip":
			host.IP = fmt.Sprintf("%v", x)
		case "alias":
			host.Name = fmt.Sprintf("%v", x)
		case "rapporteurs":
			json.Unmarshal(x.([]byte), &host.Rapporteurs)
		case "created_at":
			host.CreatedAt, _ = x.(time.Time)
		case "updated_at":
			host.UpdatedAt = x.(time.Time)
		}
	}
	return host, nil
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
		return nil, err
	}

	return credential, nil
}

func (s *PostgreSQLStore) GetCredentials(hostID string) ([]domain.Credential, error) {

	query := `
    SELECT id, host_id, username,password
    FROM credentials
    WHERE host_id=$1
  `

	rows, err := s.db.Query(query, hostID)

	if err != nil {
		return nil, fmt.Errorf("error fetching Credentials: `%+v`", err)
	}

	credentials := []domain.Credential{}

	for rows.Next() {
		credential, err := scanIntoCredential(rows)

		if err != nil {
			return nil, fmt.Errorf("erNoTokenErrorror scanning into Tenant: `%+v`", err)
		}
		credentials = append(credentials, *credential)
	}

	return credentials, nil
}

func replaceSQL(old, searchPattern string) string {
	tmpCount := strings.Count(old, searchPattern)
	for m := 1; m <= tmpCount; m++ {
		old = strings.Replace(old, searchPattern, "$"+strconv.Itoa(m), 1)
	}
	return old
}

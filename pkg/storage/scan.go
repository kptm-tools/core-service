package storage

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/kptm-tools/core-service/pkg/domain"
	"time"
)

func (s *PostgreSQLStore) CreateScansTable() error {
	query := `create table if not exists scans (
      id UUID PRIMARY KEY,
      status JSONB,
      results JSONB,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`

	_, err := s.db.Query(query)

	if err != nil {
		return err
	}

	return nil

}

func (s *PostgreSQLStore) ClearScansTable() error {
	query := `TRUNCATE TABLE scans RESTART IDENTITY CASCADE`

	_, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func (s *PostgreSQLStore) CreateScan(sc *domain.Scan) (*domain.Scan, error) {

	status, _ := json.Marshal(sc.HostsStatus)
	query := `
    INSERT INTO scans (id, status, created_at, updated_at)
    values ($1, $2, $3, $4)
    RETURNING id, created_at, updated_at`

	rows, err := s.db.Query(query, sc.ID, status, sc.CreatedAt, sc.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("error creating scan: `%v`", err)
	}

	for rows.Next() {
		return scanIntoScan(rows)
	}

	return nil, fmt.Errorf("error creating Scan")
}

func scanIntoScan(rows *sql.Rows) (*domain.Scan, error) {

	scan := new(domain.Scan)
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
			{
				z := bytes.NewBuffer(x.([]byte))
				scan.ID = z.String()
			}
		case "created_at":
			scan.CreatedAt, _ = x.(time.Time)
		case "updated_at":
			scan.UpdatedAt = x.(time.Time)
		}
	}
	return scan, nil
}

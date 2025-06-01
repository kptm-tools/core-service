package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

func (s *PostgreSQLStore) DeleteScanScheduleByID(scanScheduleID int) (bool, error) {
	query := `
    DELETE 
    FROM scan_scheduling WHERE id=$1`

	res, err := s.db.Exec(query, scanScheduleID)

	switch err {
	case nil:
		count, _ := res.RowsAffected()
		return count == 1, nil
	default:
		return false, err
	}
}

func (s *PostgreSQLStore) PatchScanScheduleByID(scanScheduleID int, scanID uuid.UUID, cronExpr string, isRepeated bool, periodName string, periodQuantity int, scheduleDate time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	query := `
    UPDATE 
    scan_scheduling SET period_name=$2, period_quantity=$3, has_period=$4, scheduled_date=$5, last_run_date=NULL, cron=$6, scan_id=$7, enabled=true, updated_at=$8 WHERE id=$1`

	tx.QueryRow(query, scanScheduleID, periodName, periodQuantity, isRepeated, scheduleDate, cronExpr, scanID, time.Now().UTC())

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
	query := `SELECT SS.id, SS.created_at, H.alias, 
       	CASE SS.has_period
			WHEN SS.has_period=true THEN CONCAT('Every ',SS.period_quantity, ' ', SS.period_name) ELSE 'Once' END AS frequency,
    	SS.scheduled_date
	FROM scan_scheduling SS 
		INNER JOIN (SELECT * FROM scans WHERE tenant_id=$1 ) S ON SS.scan_id=S.id 
		INNER JOIN hosts H ON S.host_id=H.id 
	`
	rows, err := s.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts: %w", err)
	}
	defer rows.Close()

	scanSchedules := []*domain.ScanScheduleSummary{}
	for rows.Next() {
		scanSchedule := &domain.ScanScheduleSummary{}
		if err := scanIntoScanSchedule(rows, scanSchedule); err != nil {
			return nil, fmt.Errorf("failed to scan host: %w", err)
		}
		scanSchedules = append(scanSchedules, scanSchedule)
	}

	return scanSchedules, nil
}

func scanIntoScanSchedule(rows *sql.Rows, scanSchedule *domain.ScanScheduleSummary) error {
	if err := rows.Scan(&scanSchedule.ID, &scanSchedule.CreatedDate, &scanSchedule.HostAlias, &scanSchedule.Frequency, &scanSchedule.ScheduledDate); err != nil {
		return fmt.Errorf("error scanning rows: %w", err)
	}
	return nil
}

func (s *PostgreSQLStore) GetCurrentHostIDFromScanSchedule(scanScheduleID int) (uuid.UUID, error) {
	query := `SELECT S.host_id FROM (SELECT * FROM scan_scheduling WHERE id=$1)SC INNER JOIN scans S ON SC.scan_id = S.id`
	row := s.db.QueryRow(query, scanScheduleID)
	var hostID uuid.UUID
	err := row.Scan(&hostID)
	if err != nil {
		return uuid.Nil, err
	}
	return hostID, nil
}

func (s *PostgreSQLStore) ScanScheduleEnableJob(cronExp string, hasPeriod bool, scanScheduleID int) error {
	query := `SELECT enable_cron_function( $1, $2, $3 )`
	var result int
	err := s.db.QueryRow(query, cronExp, hasPeriod, scanScheduleID).Scan(&result)
	if err != nil || result == 0 {
		return fmt.Errorf("failed to enable cron job: %w", err)
	}
	return nil
}

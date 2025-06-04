package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/repository"
)

type ScanScheduleRepository struct {
	defaultQueries *repository.Queries
}

var _ interfaces.ScanScheduleRepository = (*ScanScheduleRepository)(nil)

func NewScanScheduleRepository(queries *repository.Queries) *ScanScheduleRepository {
	return &ScanScheduleRepository{
		defaultQueries: queries,
	}
}

// getQueries retrieves the correct *repository.Queries instance from the context.
// If a transaction is active, it gets the transactional queries. Otherwise, it uses
// the defaultQueries.
func (r *ScanScheduleRepository) getQueries(ctx context.Context) *repository.Queries {
	return GetQueriesFromContext(ctx, r.defaultQueries)
}

func (r *ScanScheduleRepository) CreateScanSchedule(
	ctx context.Context,
	schedule domain.ScanSchedule,
) (*domain.ScanSchedule, error) {
	queries := r.getQueries(ctx)

	var sqlPeriodName repository.NullPeriodEnum
	var sqlPeriodQuantity sql.NullInt32

	if schedule.HasPeriod {
		if schedule.PeriodName != nil {
			sqlPeriodName = repository.NullPeriodEnum{PeriodEnum: repository.PeriodEnum(*schedule.PeriodName), Valid: true}
		} else {
			sqlPeriodName.Valid = false
		}

		if schedule.PeriodQuantity != nil {
			sqlPeriodQuantity = sql.NullInt32{Int32: *schedule.PeriodQuantity, Valid: true}
		} else {
			sqlPeriodQuantity.Valid = false
		}
	} else {
		sqlPeriodName.Valid = false
		sqlPeriodQuantity.Valid = false
	}

	var sqlScheduledDate sql.NullTime
	if schedule.ScheduledDate != nil {
		sqlScheduledDate = sql.NullTime{Time: *schedule.ScheduledDate, Valid: true}
	} else {
		sqlScheduledDate.Valid = false
	}

	params := repository.CreateScanScheduleParams{
		ScanID:         schedule.ScanID,
		PeriodName:     sqlPeriodName,
		PeriodQuantity: sqlPeriodQuantity,
		Enabled:        schedule.Enabled,
		HasPeriod:      schedule.HasPeriod,
		Cron:           schedule.CronExpression,
		ScheduledDate:  sqlScheduledDate,
	}

	dbSchedule, err := queries.CreateScanSchedule(ctx, params)
	if err != nil {
		return nil, err
	}
	return r.dbScanScheduleToDomain(&dbSchedule), nil
}

func (r *ScanScheduleRepository) GetScanScheduleByID(ctx context.Context, scheduleID int) (*domain.ScanSchedule, error) {
	queries := r.getQueries(ctx)
	dbSchedule, err := queries.GetScanSchedulebyID(ctx, int32(scheduleID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, customerrors.ErrScheduleNotFound
		}
		return nil, err
	}
	return r.dbScanScheduleToDomain(&dbSchedule), nil
}

func (r *ScanScheduleRepository) GetScanSchedulesByTenantID(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error) {
	queries := r.getQueries(ctx)
	dbSchedules, err := queries.ListScanScheduleSummariesByTenant(ctx, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []domain.ScanScheduleSummary{}, nil
		}
		return nil, err
	}

	summaries := make([]domain.ScanScheduleSummary, len(dbSchedules))
	for i, dbSchedule := range dbSchedules {
		summary := domain.ScanScheduleSummary{
			ID:        int(dbSchedule.ID),
			HostAlias: dbSchedule.HostAlias,
			Frequency: dbSchedule.Frequency,
		}
		if dbSchedule.CreatedDate.Valid {
			summary.CreatedDate = dbSchedule.CreatedDate.Time
		}
		if dbSchedule.ScheduledDate.Valid {
			summary.ScheduledDate = dbSchedule.ScheduledDate.Time
		}
		summaries[i] = summary
	}
	return summaries, nil
}

func (r *ScanScheduleRepository) DeleteScanScheduleByID(ctx context.Context, scheduleID int) (bool, error) {
	queries := r.getQueries(ctx)
	err := queries.DeleteScanSchedule(ctx, int32(scheduleID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, customerrors.ErrScanNotFound
		}
		return false, err
	}
	return true, nil
}

func (r *ScanScheduleRepository) EnableJob(ctx context.Context, cronExp string, hasPeriod bool, scheduleID int) error {
	queries := r.getQueries(ctx)
	params := repository.EnableScanScheduleJobParams{
		CronExp:        cronExp,
		PhasPeriod:     hasPeriod,
		ScanScheduleID: int32(scheduleID),
	}
	return queries.EnableScanScheduleJob(ctx, params)
}

func (r *ScanScheduleRepository) DisableJob(ctx context.Context, scheduleID int, withDelete bool) error {
	queries := r.getQueries(ctx)
	params := repository.DisableScanScheduleJobParams{
		Scanscheduleid: int32(scheduleID),
		Withdelete:     withDelete,
	}
	return queries.DisableScanScheduleJob(ctx, params)
}

func (r *ScanScheduleRepository) PatchScanScheduleByID(
	ctx context.Context,
	scheduleID int,
	scanID uuid.UUID,
	cronExpr string,
	isRepeated bool,
	periodName string,
	periodQuantity int,
	scheduleDate time.Time,
) error {
	queries := r.getQueries(ctx)
	params := repository.PatchScanScheduleByIDParams{
		ID:             int32(scheduleID),
		PeriodName:     repository.NullPeriodEnum{PeriodEnum: repository.PeriodEnum(periodName), Valid: true},
		PeriodQuantity: sql.NullInt32{Int32: int32(periodQuantity), Valid: true},
		HasPeriod:      true,
		ScheduledDate:  sql.NullTime{Time: scheduleDate, Valid: true},
		Cron:           cronExpr,
		ScanID:         scanID,
		UpdatedAt:      sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}
	return queries.PatchScanScheduleByID(ctx, params)
}

func (r *ScanScheduleRepository) UpdateScanScheduling(
	ctx context.Context,
	scanID uuid.UUID,
	scanScheduleID int,
) error {
	queries := r.getQueries(ctx)
	params := repository.UpdateScanSchedulingParams{
		ID:     int32(scanScheduleID),
		ScanID: scanID,
	}
	return queries.UpdateScanScheduling(ctx, params)
}

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

func (s *PostgreSQLStore) PatchScanScheduleByID(
	scanScheduleID int,
	scanID uuid.UUID,
	cronExpr string,
	isRepeated bool,
	periodName string,
	periodQuantity int,
	scheduleDate time.Time,
) error {
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

func (r *ScanScheduleRepository) dbScanScheduleToDomain(dbSchedule *repository.ScanScheduling) *domain.ScanSchedule {
	// dbSchedule is the struct sqlc generated for the 'scan_scheduling' table row
	var domainPeriodName *domain.PeriodEnum
	if dbSchedule.PeriodName.Valid { // Assuming PeriodName in sqlc struct is *domain.PeriodEnum
		domainPeriodName = (*domain.PeriodEnum)(&dbSchedule.PeriodName.PeriodEnum)
	}

	var domainPeriodQuantity *int32
	if dbSchedule.PeriodQuantity.Valid {
		val := dbSchedule.PeriodQuantity.Int32
		domainPeriodQuantity = &val
	}

	var domainScheduledDate *time.Time
	if dbSchedule.ScheduledDate.Valid {
		val := dbSchedule.ScheduledDate.Time
		domainScheduledDate = &val
	}

	var domainLastRunDate *time.Time
	if dbSchedule.LastRunDate.Valid { // Assuming LastRunDate is sql.NullTime in sqlc struct
		val := dbSchedule.LastRunDate.Time
		domainLastRunDate = &val
	}

	var domainCronJobID *int64
	if dbSchedule.CronJobID.Valid { // Assuming CronJobID is sql.NullInt64 in sqlc struct
		val := dbSchedule.CronJobID.Int64
		domainCronJobID = &val
	}

	var domainCreatedAt *time.Time
	valCreatedAt := dbSchedule.CreatedAt
	domainCreatedAt = &valCreatedAt.Time

	var domainUpdatedAt *time.Time
	valUpdatedAt := dbSchedule.UpdatedAt // Adjust if dbSchedule.UpdatedAt is pgtype.Timestamptz
	domainUpdatedAt = &valUpdatedAt.Time

	return &domain.ScanSchedule{
		ID:             dbSchedule.ID, // Assuming ID is int32 from SERIAL
		ScanID:         dbSchedule.ScanID,
		HostID:         dbSchedule.HostID,
		LastRunDate:    domainLastRunDate,
		ScheduledDate:  domainScheduledDate,
		PeriodName:     domainPeriodName,
		PeriodQuantity: domainPeriodQuantity,
		Enabled:        dbSchedule.Enabled,
		HasPeriod:      dbSchedule.HasPeriod,
		CronExpression: dbSchedule.Cron,
		CronJobID:      domainCronJobID,
		CreatedAt:      domainCreatedAt,
		UpdatedAt:      domainUpdatedAt,
	}
}

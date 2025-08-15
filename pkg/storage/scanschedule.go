package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	repository "github.com/kptm-tools/core-service/db"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
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
		HostID:         schedule.HostID,
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

func (r *ScanScheduleRepository) GetScanScheduleByID(ctx context.Context, scheduleID int32) (*domain.ScanSchedule, error) {
	queries := r.getQueries(ctx)

	dbSchedule, err := queries.GetScanSchedulebyID(ctx, scheduleID)
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

func (r *ScanScheduleRepository) DeleteScanScheduleByID(ctx context.Context, scheduleID int32) (bool, error) {
	queries := r.getQueries(ctx)
	err := queries.DeleteScanSchedule(ctx, scheduleID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, customerrors.ErrScanNotFound
		}
		return false, err
	}
	return true, nil
}

func (r *ScanScheduleRepository) EnableJob(ctx context.Context, cronExp string, hasPeriod bool, scheduleID int32) error {
	queries := r.getQueries(ctx)
	params := repository.EnableScanScheduleJobParams{
		CronExp:        cronExp,
		PhasPeriod:     hasPeriod,
		ScanScheduleID: scheduleID,
	}
	return queries.EnableScanScheduleJob(ctx, params)
}

func (r *ScanScheduleRepository) DisableJob(ctx context.Context, scheduleID int32, withDelete bool) error {
	queries := r.getQueries(ctx)
	params := repository.DisableScanScheduleJobParams{
		Scanscheduleid: scheduleID,
		Withdelete:     withDelete,
	}
	return queries.DisableScanScheduleJob(ctx, params)
}

func (r *ScanScheduleRepository) PatchScanScheduleByID(
	ctx context.Context,
	scheduleID int32,
	scanID uuid.UUID,
	cronExpr string,
	isRepeated bool,
	periodName string,
	periodQuantity int32,
	scheduleDate time.Time,
) error {
	queries := r.getQueries(ctx)
	params := repository.PatchScanScheduleByIDParams{
		ID:             scheduleID,
		PeriodName:     repository.NullPeriodEnum{PeriodEnum: repository.PeriodEnum(periodName), Valid: true},
		PeriodQuantity: sql.NullInt32{Int32: periodQuantity, Valid: true},
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
	scanScheduleID int32,
) error {
	queries := r.getQueries(ctx)
	params := repository.UpdateScanSchedulingParams{
		ID:     scanScheduleID,
		ScanID: scanID,
	}
	return queries.UpdateScanScheduling(ctx, params)
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

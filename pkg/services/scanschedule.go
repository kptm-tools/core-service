package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/utils"
)

type ScanScheduleService struct {
	txManager    interfaces.TxManager
	scanRepo     interfaces.ScanRepository
	scheduleRepo interfaces.ScanScheduleRepository
}

var _ interfaces.IScanScheduleService = (*ScanScheduleService)(nil)

func NewScanScheduleService(
	transactionManager interfaces.TxManager,
	scanRepository interfaces.ScanRepository,
	scanScheduleRepository interfaces.ScanScheduleRepository,
) *ScanScheduleService {
	return &ScanScheduleService{
		txManager:    transactionManager,
		scanRepo:     scanRepository,
		scheduleRepo: scanScheduleRepository,
	}
}

func (s *ScanScheduleService) CreateScanSchedule(
	ctx context.Context,
	scanID uuid.UUID,
	scheduleAt time.Time,
	frequency *domain.RepeatSchedule,
	hostID uuid.UUID,
) (*domain.ScanSchedule, error) {
	var hasPeriod bool
	var cronExpr string
	var periodName domain.PeriodEnum
	var periodQuantity int32
	if frequency != nil {
		hasPeriod = true
		periodName = frequency.UnitOfFrequency
		periodQuantity = int32(frequency.Quantity)
	}
	if !hasPeriod {
		cronExpr = fmt.Sprintf("%d %d %d %d *", scheduleAt.Minute(), scheduleAt.Hour(), scheduleAt.Day(), scheduleAt.Month())
	} else {
		cronExpr = fmt.Sprintf("%d %d * * *", scheduleAt.Minute(), scheduleAt.Hour())
	}

	scheduleToCreate := domain.ScanSchedule{
		HostID:         hostID,
		ScanID:         scanID,
		CronExpression: cronExpr,
		HasPeriod:      hasPeriod,
		Enabled:        true,
		ScheduledDate:  &scheduleAt,
		// PeriodName and PeriodQuantity are pointers, nil if not IsRepeated
		PeriodName:     &periodName,
		PeriodQuantity: &periodQuantity,
	}

	createdSchedule, err := s.scheduleRepo.CreateScanSchedule(ctx, scheduleToCreate)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan schedle in database: %w", err)
	}
	return createdSchedule, nil
}

func (s *ScanScheduleService) DeleteScanScheduleByID(ctx context.Context, scanScheduleID int32) (bool, error) {
	isDeleted, err := s.scheduleRepo.DeleteScanScheduleByID(ctx, scanScheduleID)
	if err != nil {
		return false, fmt.Errorf("failed to delete scan schedule by ID: %w", err)
	}
	return isDeleted, nil
}

func (s *ScanScheduleService) PatchScanSchedule(
	ctx context.Context,
	scanScheduleID int32,
	frequency *domain.RepeatSchedule,
	scheduleAt time.Time,
	tenantID, operatorID, hostID uuid.UUID,
) error {
	errDisableCurrentJob := s.scheduleRepo.DisableJob(ctx, scanScheduleID, true)
	if errDisableCurrentJob != nil {
		return errDisableCurrentJob
	}

	commonScanData := domain.NewScan(hostID, tenantID, operatorID, &scheduleAt)
	commonScanData.TenantID = tenantID
	commonScanData.OperatorID = operatorID
	commonScanData.HostID = hostID
	commonScanData.Status = enums.StatusScheduled.String()
	dataScan, err := s.scanRepo.CreateScan(ctx, *commonScanData)
	if err != nil {
		return fmt.Errorf("failed to create new scan for update scan scheduling: %w", err)
	}
	var isRepeated bool
	var cronExpr string
	var periodName string
	var periodQuantity int32
	if frequency != nil {
		isRepeated = true
		periodName = string(frequency.UnitOfFrequency)
		periodQuantity, err = utils.SafeIntToInt32(frequency.Quantity)
		if err != nil {
			return err
		}
	}
	if !isRepeated {
		cronExpr = fmt.Sprintf("%d %d %d %d *", scheduleAt.Minute(), scheduleAt.Hour(), scheduleAt.Day(), scheduleAt.Month())
	} else {
		cronExpr = fmt.Sprintf("%d %d * * *", scheduleAt.Minute(), scheduleAt.Hour())
	}
	errEnableJob := s.scheduleRepo.EnableJob(ctx, cronExpr, isRepeated, scanScheduleID)
	if errEnableJob != nil {
		return errEnableJob
	}
	errPatchScanSchedule := s.scheduleRepo.PatchScanScheduleByID(ctx, scanScheduleID, dataScan.ID, cronExpr, isRepeated, periodName, periodQuantity, scheduleAt)
	if errPatchScanSchedule != nil {
		return errPatchScanSchedule
	}

	return nil
}

func (s *ScanScheduleService) GetScanSchedulesByTenantID(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]domain.ScanScheduleSummary, error) {
	return s.scheduleRepo.GetScanSchedulesByTenantID(ctx, tenantID)
}

func (s *ScanScheduleService) GetCurrentHostID(ctx context.Context, scanScheduleID int32) (uuid.UUID, error) {
	schedule, err := s.scheduleRepo.GetScanScheduleByID(ctx, scanScheduleID)
	if err != nil {
		return uuid.Nil, err
	}
	return schedule.HostID, nil
}

func (s *ScanScheduleService) UpdateScanScheduleScanID(
	ctx context.Context,
	scanID uuid.UUID,
	scanScheduleID int32,
) error {
	if err := s.scheduleRepo.UpdateScanScheduling(ctx, scanID, scanScheduleID); err != nil {
		return fmt.Errorf("failed to update scan scheduling: %w", err)
	}
	return nil
}

func (s *ScanScheduleService) ScanScheduleDisableJob(ctx context.Context, scanScheduleID int32) error {
	return s.scheduleRepo.DisableJob(ctx, scanScheduleID, false)
}

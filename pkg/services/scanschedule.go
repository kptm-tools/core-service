package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type ScanScheduleService struct {
	storage interfaces.IStorage
}

var _ interfaces.IScanScheduleService = (*ScanScheduleService)(nil)

func NewScanScheduleService(storage interfaces.IStorage) *ScanScheduleService {
	return &ScanScheduleService{
		storage: storage,
	}
}

func (s ScanScheduleService) CreateScanScheduling(
	ctx context.Context,
	scanID uuid.UUID,
	scheduleAt time.Time,
	frequency *domain.RepeatSchedule,
) error {
	var isRepeated bool
	var cronExpr string
	var periodName string
	var periodQuantity int
	if frequency != nil {
		isRepeated = true
		periodName = string(frequency.UnitOfFrequency)
		periodQuantity = frequency.Quantity
	}
	if !isRepeated {
		cronExpr = fmt.Sprintf("%d %d %d %d *", scheduleAt.Minute(), scheduleAt.Hour(), scheduleAt.Day(), scheduleAt.Month())
	} else {
		cronExpr = fmt.Sprintf("%d %d * * *", scheduleAt.Minute(), scheduleAt.Hour())
	}

	err := s.storage.CreateScanScheduling(scanID, cronExpr, isRepeated, periodName, periodQuantity, scheduleAt)
	if err != nil {
		return err
	}
	return nil
}

func (s ScanScheduleService) DeleteScanScheduleByID(scanScheduleID int) (bool, error) {
	isDeleted, err := s.storage.DeleteScanScheduleByID(scanScheduleID)
	if err != nil {
		return false, err
	}

	return isDeleted, nil
}

func (s *ScanScheduleService) PatchScanSchedule(
	scanScheduleID int,
	frequency *domain.RepeatSchedule,
	scheduleAt time.Time,
	tenantID, operatorID, hostID uuid.UUID,
) error {
	errDisableCurrentJob := s.storage.ScanScheduleDisableJob(scanScheduleID, true)
	if errDisableCurrentJob != nil {
		return errDisableCurrentJob
	}

	commonScanData := domain.NewScan(hostID, tenantID, operatorID, &scheduleAt)
	commonScanData.TenantID = tenantID
	commonScanData.OperatorID = operatorID
	commonScanData.HostID = hostID
	commonScanData.Status = enums.StatusScheduled.String()
	dataScan, errCreationScan := s.storage.CreateScan(commonScanData)
	if errCreationScan != nil {
		return fmt.Errorf("failed to create new scan for update scan scheduling: %w", errCreationScan)
	}
	var isRepeated bool
	var cronExpr string
	var periodName string
	var periodQuantity int
	if frequency != nil {
		isRepeated = true
		periodName = string(frequency.UnitOfFrequency)
		periodQuantity = frequency.Quantity
	}
	if !isRepeated {
		cronExpr = fmt.Sprintf("%d %d %d %d *", scheduleAt.Minute(), scheduleAt.Hour(), scheduleAt.Day(), scheduleAt.Month())
	} else {
		cronExpr = fmt.Sprintf("%d %d * * *", scheduleAt.Minute(), scheduleAt.Hour())
	}
	errEnableJob := s.storage.ScanScheduleEnableJob(cronExpr, isRepeated, scanScheduleID)
	if errEnableJob != nil {
		return errEnableJob
	}
	errPatchScanSchedule := s.storage.PatchScanScheduleByID(scanScheduleID, dataScan.ID, cronExpr, isRepeated, periodName, periodQuantity, scheduleAt)
	if errPatchScanSchedule != nil {
		return errPatchScanSchedule
	}

	return nil
}

func (s *ScanScheduleService) GetScanSchedulesByTenantID(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
	return s.storage.GetScanSchedules(tenantID)
}

func (s *ScanScheduleService) GetCurrentHostID(scanScheduleID int) (uuid.UUID, error) {
	hostID, errGetHostID := s.storage.GetCurrentHostIDFromScanSchedule(scanScheduleID)
	if errGetHostID != nil {
		return hostID, fmt.Errorf("failed to get current host ID: %w", errGetHostID)
	}
	return hostID, nil
}

func (s *ScanScheduleService) UpdateScanScheduleScanID(ctx context.Context, scanID uuid.UUID, scanScheduleID int) error {
}

func (s *ScanScheduleService) ScanScheduleDisableJob(ctx context.Context, scanScheduleID int) error {
	return s.storage.ScanScheduleDisableJob(scanScheduleID, false)
}

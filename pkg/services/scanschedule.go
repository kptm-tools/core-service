package services

import (
	"fmt"
	"github.com/google/uuid"
	"time"

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

func (s ScanScheduleService) DeleteScanScheduleByID(scanScheduleID int) (bool, error) {
	isDeleted, err := s.storage.DeleteScanScheduleByID(scanScheduleID)

	if err != nil {
		return false, err
	}

	return isDeleted, nil
}

func (s ScanScheduleService) InsertScanScheduling(scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) error {
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

func (s ScanScheduleService) PatchScanSchedule(scanScheduleID int, scheduleProgram domain.RepeatSchedule, scheduleDate time.Time) error {
	return s.storage.PatchScanScheduleByID(scanScheduleID, scheduleProgram, scheduleDate)
}

func (s ScanScheduleService) GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
	return s.storage.GetScanSchedules(tenantID)
}

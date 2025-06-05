package mock_services

import (
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type MockScanScheduleService struct {
	MockGetCurrentHostID     func(scanScheduleID int) (int, error)
	MockGetScanSchedules     func(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error)
	MockPatchScanSchedule    func(scanScheduleID int, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID string, operatorID string, hostID int) error
	MockDeleteScanSchedule   func(scanScheduleID int) error
	MockInsertScanScheduling func(scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) error
}

func (m *MockScanScheduleService) InsertScanScheduling(scanID uuid.UUID, scheduleAt time.Time, frequency *domain.RepeatSchedule) error {
	if m.MockInsertScanScheduling != nil {
		return m.MockInsertScanScheduling(scanID, scheduleAt, frequency)
	}
	return nil
}

func (m *MockScanScheduleService) DeleteScanScheduleByID(i int) (bool, error) {
	if m.MockDeleteScanSchedule != nil {
		return true, nil
	}
	return false, nil
}

func (m *MockScanScheduleService) PatchScanSchedule(scanScheduleID int, frequency *domain.RepeatSchedule, scheduleAt time.Time, tenantID string, operatorID string, hostID int) error {
	if m.MockPatchScanSchedule == nil {
		return m.MockPatchScanSchedule(scanScheduleID, frequency, scheduleAt, tenantID, operatorID, hostID)
	}
	return nil
}

func (m *MockScanScheduleService) GetScanSchedules(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
	if m.MockGetScanSchedules != nil {
		return m.MockGetScanSchedules(tenantID)
	}
	return []*domain.ScanScheduleSummary{}, nil
}

func (m *MockScanScheduleService) GetCurrentHostID(scanScheduleID int) (int, error) {
	if m.MockGetCurrentHostID != nil {
		return m.MockGetCurrentHostID(scanScheduleID)
	}
	return -1, nil // Default behavior if mock function not set
}

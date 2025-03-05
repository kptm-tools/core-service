package services

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_InsertScanScheduling_Success(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockCreateScanScheduling: func(scanID uuid.UUID, cronExpression string, isRepeated bool, periodName string, periodQuantity int, scheduledDate time.Time) error {
			return nil
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errInsert := scanScheduleService.InsertScanScheduling(uuid.New(), time.Now().UTC(), nil)
	assert.NoError(t, errInsert)
}

func Test_InsertScanScheduling_Error(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockCreateScanScheduling: func(scanID uuid.UUID, cronExpression string, isRepeated bool, periodName string, periodQuantity int, scheduledDate time.Time) error {
			return fmt.Errorf("failed to insert scan scheduling: ")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errInsert := scanScheduleService.InsertScanScheduling(uuid.New(), time.Now().UTC(), nil)
	assert.Error(t, errInsert)
	assert.Contains(t, errInsert.Error(), "failed to insert scan scheduling")
}

func Test_DeleteScanScheduleByID_Error(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockDeleteScanScheduleByID: func(scanScheduleID int) (bool, error) {
			return false, fmt.Errorf("failed to delete scan schedule")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	isDeleted, errDelete := scanScheduleService.DeleteScanScheduleByID(1)
	assert.Error(t, errDelete)
	assert.Equal(t, false, isDeleted)

}

func Test_DeleteScanScheduleByID_Success(t *testing.T) {
	mockStore := &mocks.MockStorage{}
	scanScheduleService := NewScanScheduleService(mockStore)
	isDeleted, errDelete := scanScheduleService.DeleteScanScheduleByID(1)
	assert.NoError(t, errDelete)
	assert.True(t, isDeleted)
}

func Test_GetScanSchedules_Error(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockGetScanSchedules: func(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
			return nil, fmt.Errorf("failed to get scan schedules")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	scanSchedules, errGet := scanScheduleService.GetScanSchedules(uuid.New())
	assert.Error(t, errGet)
	assert.Nil(t, scanSchedules)
}

func Test_GetScanSchedules_Success_NoRows(t *testing.T) {
	mockStore := &mocks.MockStorage{}
	scanScheduleService := NewScanScheduleService(mockStore)
	scanSchedules, errGet := scanScheduleService.GetScanSchedules(uuid.New())
	assert.NoError(t, errGet)
	assert.Empty(t, scanSchedules)
}

func Test_GetScanSchedules_Success(t *testing.T) {
	sampleSchedules := []*domain.ScanScheduleSummary{
		{
			ID:            1,
			CreatedDate:   time.Now(),
			HostAlias:     "peru",
			Frequency:     "Every day",
			ScheduledDate: time.Now().Add(24 * time.Hour).UTC(),
		},
		{
			ID:            2,
			HostAlias:     "chile",
			Frequency:     "Every week",
			ScheduledDate: time.Now().Add(7 * 24 * time.Hour).UTC(),
		},
	}
	mockStore := &mocks.MockStorage{
		MockGetScanSchedules: func(tenantID uuid.UUID) ([]*domain.ScanScheduleSummary, error) {
			return sampleSchedules, nil
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	scanSchedules, errGet := scanScheduleService.GetScanSchedules(uuid.New())
	assert.NoError(t, errGet)
	assert.Len(t, scanSchedules, 2)
}

func Test_GetCurrentHostID_Error(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockGetCurrentHostIDFromScanSchedule: func(scanScheduleID int) (int, error) {
			return -1, errors.New("failed to get current host id")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	id, errGetCurrent := scanScheduleService.GetCurrentHostID(1)
	assert.Error(t, errGetCurrent)
	assert.Equal(t, -1, id)
	assert.Contains(t, errGetCurrent.Error(), "failed to get current host id")
}

func Test_GetCurrentHostID_Success(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockGetCurrentHostIDFromScanSchedule: func(scanScheduleID int) (int, error) {
			return 1, nil
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	id, errGetCurrent := scanScheduleService.GetCurrentHostID(1)
	assert.NoError(t, errGetCurrent)
	assert.Equal(t, 1, id)
}

func Test_PatchScanSchedule_Error_Disable(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockScanScheduleDisableJob: func(scanScheduleID int, withDelete bool) error {
			return errors.New("failed to unregister job")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errPatch := scanScheduleService.PatchScanSchedule(1, nil, time.Now(), "test-tenant", "test-operator", 1)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to unregister job")
}

func Test_PatchScanSchedule_Error_CreateScan(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockCreateScan: func(scan *domain.Scan) (*domain.Scan, error) {
			return nil, fmt.Errorf("failed to create scan schedule")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errPatch := scanScheduleService.PatchScanSchedule(1, nil, time.Now(), "test-tenant", "test-operator", 1)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to create scan schedule")
}

func Test_PatchScanSchedule_Error_EnableJob(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockScanScheduleEnableJob: func(cronExp string, hasPeriod bool, scanScheduleID int) error {
			return errors.New("failed to enable job")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errPatch := scanScheduleService.PatchScanSchedule(1, nil, time.Now(), "test-tenant", "test-operator", 1)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to enable job")
}

func Test_PatchScanSchedule_Error_Patch(t *testing.T) {
	scanData := domain.NewScan(time.Now())
	mockStore := &mocks.MockStorage{
		MockCreateScan: func(scan *domain.Scan) (*domain.Scan, error) {
			return scanData, nil
		},
		MockPatchScanScheduleByID: func(scanScheduleID int, scanID uuid.UUID, cronExpr string, isRepeated bool, periodName string, periodQuantity int, scheduleDate time.Time) error {
			return errors.New("failed to patch scan schedule")
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errPatch := scanScheduleService.PatchScanSchedule(1, nil, time.Now(), "test-tenant", "test-operator", 1)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to patch scan schedule")
}

func Test_PatchScanSchedule_Success(t *testing.T) {
	scanData := domain.NewScan(time.Now())
	mockStore := &mocks.MockStorage{
		MockCreateScan: func(scan *domain.Scan) (*domain.Scan, error) {
			return scanData, nil
		},
	}
	scanScheduleService := NewScanScheduleService(mockStore)
	errPatch := scanScheduleService.PatchScanSchedule(1, nil, time.Now(), "test-tenant", "test-operator", 1)
	assert.NoError(t, errPatch)
}

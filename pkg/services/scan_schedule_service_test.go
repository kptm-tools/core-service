package services

import (
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

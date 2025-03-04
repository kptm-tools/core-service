package services

import (
	"fmt"
	"github.com/google/uuid"
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

package services

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/mocks"
	"github.com/stretchr/testify/assert"
)

func Test_GetReportsByTenantID_NoReports(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockGetReportsByTenantID: func(tenantID string) ([]*domain.ReportItem, error) {
			return nil, nil
		},
	}

	scansService := NewScanService(mockStore)

	tenantID := "test-tenant"
	reports, err := scansService.GetAllReportsForTenant(tenantID)

	assert.NoError(t, err)
	assert.Empty(t, reports)
}

func Test_GetReportsByTenantID_StorageError(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockGetReportsByTenantID: func(tenantID string) ([]*domain.ReportItem, error) {
			return nil, errors.New("database connection failed")
		},
	}

	scansService := NewScanService(mockStore)

	tenantID := "test-tenant"
	reports, err := scansService.GetAllReportsForTenant(tenantID)

	assert.Error(t, err)
	assert.Nil(t, reports)
	assert.Contains(t, err.Error(), "failed to fetch reports from storage")
}

func Test_GetReportsByTenantID_Success(t *testing.T) {
	sampleReports := []*domain.ReportItem{
		{
			ScanID:          uuid.New(),
			HostName:        "example.com",
			IP:              "1.2.3.4",
			ScanDate:        time.Now(),
			TotalSeverities: 10,
			CommentStatus:   domain.CommentStatusNewComment,
		},
		{
			ScanID:          uuid.New(),
			HostName:        "example2.com",
			IP:              "5.6.7.8",
			ScanDate:        time.Now(),
			TotalSeverities: 20,
			CommentStatus:   domain.CommentStatusNewComment,
		},
	}
	mockStore := &mocks.MockStorage{
		MockGetReportsByTenantID: func(tenantID string) ([]*domain.ReportItem, error) {
			return sampleReports, nil
		},
	}

	scansService := NewScanService(mockStore)

	tenantID := "test-tenant"
	reports, err := scansService.GetAllReportsForTenant(tenantID)

	assert.NoError(t, err)
	assert.NotEmpty(t, reports)
	assert.Equal(t, len(sampleReports), len(reports))
}

func Test_ScanScheduleDisableJob_Error(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockScanScheduleDisableJob: func(scanScheduleID int, withDelete bool) error {
			return errors.New("failed to unregister job")
		},
	}
	scansService := NewScanService(mockStore)
	errDisable := scansService.ScanScheduleDisableJob(1)
	assert.Error(t, errDisable)
	assert.Contains(t, errDisable.Error(), "failed to unregister job")
}

func Test_ScanScheduleDisableJob_Success(t *testing.T) {
	mockStore := &mocks.MockStorage{}
	scansService := NewScanService(mockStore)
	errDisable := scansService.ScanScheduleDisableJob(1)
	assert.NoError(t, errDisable)
}

func Test_UpdateScanScheduling_Error(t *testing.T) {
	mockStore := &mocks.MockStorage{
		MockUpdateScanScheduling: func(scanID uuid.UUID, scanScheduleID int) error {
			return errors.New("failed to update scan scheduling")
		},
	}
	scansService := NewScanService(mockStore)
	errUpdate := scansService.UpdateScanScheduleScanID(uuid.New(), 1)
	assert.Error(t, errUpdate)
	assert.Contains(t, errUpdate.Error(), "failed to update scan scheduling")
}

func Test_UpdateScanScheduling_Success(t *testing.T) {
	mockStore := &mocks.MockStorage{}
	scansService := NewScanService(mockStore)
	errUpdate := scansService.UpdateScanScheduleScanID(uuid.New(), 1)
	assert.NoError(t, errUpdate)
}

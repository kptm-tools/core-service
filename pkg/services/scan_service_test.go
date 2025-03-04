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

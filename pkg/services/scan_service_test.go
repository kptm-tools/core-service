package services_test

import (
	"context"
	"errors"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mock "github.com/kptm-tools/core-service/pkg/mocks/storage"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/stretchr/testify/assert"
)

func Test_GetReportsByTenantID_NoReports(t *testing.T) {
	// mockStore := &mocks.MockStorage{
	// 	MockGetReportsByTenantID: func(tenantID string) ([]*domain.ReportItem, error) {
	// 		return nil, nil
	// 	},
	// }
	mockScanRepo := &mock.MockScanRepo{
		MockGetReportsByTenantID: func(ctx context.Context, u uuid.UUID) ([]domain.ReportItem, error) {
			return []domain.ReportItem{}, nil
		},
	}

	scansService := services.NewScanService(
		&mock.MockVulnerabilityRepo{},
		mockScanRepo,
		&mock.MockHostRepo{},
		&mock.MockScanResultRepo{},
	)

	tenantID := uuid.Nil
	reports, err := scansService.GetAllReportsForTenant(context.Background(), tenantID)

	assert.NoError(t, err)
	assert.Empty(t, reports)
}

func Test_GetReportsByTenantID_StorageError(t *testing.T) {
	mockScanRepo := &mock.MockScanRepo{
		MockGetReportsByTenantID: func(ctx context.Context, u uuid.UUID) ([]domain.ReportItem, error) {
			return nil, errors.New("database connection failed")
		},
	}

	scansService := services.NewScanService(
		&mock.MockVulnerabilityRepo{},
		mockScanRepo,
		&mock.MockHostRepo{},
		&mock.MockScanResultRepo{},
	)

	reports, err := scansService.GetAllReportsForTenant(context.Background(), uuid.Nil)

	assert.Error(t, err)
	assert.Nil(t, reports)
	assert.Contains(t, err.Error(), "failed to fetch reports from storage")
}

func Test_GetReportsByTenantID_Success(t *testing.T) {
	sampleReports := []domain.ReportItem{
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
	mockScanRepo := &mock.MockScanRepo{
		MockGetReportsByTenantID: func(ctx context.Context, u uuid.UUID) ([]domain.ReportItem, error) {
			return sampleReports, nil
		},
	}

	scansService := services.NewScanService(
		&mock.MockVulnerabilityRepo{},
		mockScanRepo,
		&mock.MockHostRepo{},
		&mock.MockScanResultRepo{},
	)

	reports, err := scansService.GetAllReportsForTenant(context.Background(), uuid.Nil)

	assert.NoError(t, err)
	assert.NotEmpty(t, reports)
	assert.Equal(t, len(sampleReports), len(reports))
}

func Test_ScanScheduleDisableJob_Error(t *testing.T) {
	mockScheduleRepo := &mock.MockScanScheduleRepo{
		MockDisableJob: func(ctx context.Context, i int32, b bool) error {
			return errors.New("failed to unregister job")
		},
	}

	scansService := services.NewScanScheduleService(
		&mock.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mock.MockScanRepo{},
		mockScheduleRepo,
	)
	errDisable := scansService.ScanScheduleDisableJob(context.Background(), 1)
	assert.Error(t, errDisable)
	assert.Contains(t, errDisable.Error(), "failed to unregister job")
}

func Test_ScanScheduleDisableJob_Success(t *testing.T) {
	scansService := services.NewScanScheduleService(
		&mock.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error {
				return nil
			},
		},
		&mock.MockScanRepo{},
		&mock.MockScanScheduleRepo{
			MockDisableJob: func(ctx context.Context, i int32, b bool) error { return nil },
		},
	)

	errDisable := scansService.ScanScheduleDisableJob(context.Background(), 1)
	assert.NoError(t, errDisable)
}

func Test_UpdateScanScheduling_Error(t *testing.T) {
	scansService := services.NewScanScheduleService(
		&mock.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error {
				return nil
			},
		},
		&mock.MockScanRepo{},
		&mock.MockScanScheduleRepo{
			MockUpdateScanScheduling: func(ctx context.Context, u uuid.UUID, i int32) error {
				return errors.New("failed to update scan scheduling")
			},
		},
	)

	errUpdate := scansService.UpdateScanScheduleScanID(context.Background(), uuid.Nil, 1)
	assert.Error(t, errUpdate)
	assert.Contains(t, errUpdate.Error(), "failed to update scan scheduling")
}

func Test_UpdateScanScheduling_Success(t *testing.T) {
	scansService := services.NewScanScheduleService(
		&mock.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error {
				return nil
			},
		},
		&mock.MockScanRepo{},
		&mock.MockScanScheduleRepo{
			MockUpdateScanScheduling: func(ctx context.Context, u uuid.UUID, i int32) error {
				return nil
			},
		},
	)

	errUpdate := scansService.UpdateScanScheduleScanID(context.Background(), uuid.Nil, 1)
	assert.NoError(t, errUpdate)
}

func Test_GetInformationGatheredResults_ErrorScanNotFound(t *testing.T) {
	mockScaResultsRepo := &mock.MockScanResultRepo{
		MockGetScanResultsByScanID: func(ctx context.Context, scanID uuid.UUID, tools []string) ([]domain.ScanResult, error) {
			return nil, customerrors.ErrScanNotFound
		},
	}

	scanService := services.NewScanService(
		&mock.MockVulnerabilityRepo{},
		&mock.MockScanRepo{},
		&mock.MockHostRepo{},
		mockScaResultsRepo,
	)
	_, errGetScan := scanService.GetInformationGatheredResults(context.Background(), uuid.New())
	assert.Error(t, errGetScan)
	assert.Contains(t, errGetScan.Error(), "scan not found")
}

func Test_GetInformationGatheredResults_Success(t *testing.T) {
	mockScaResultsRepo := &mock.MockScanResultRepo{
		MockGetScanResultsByScanID: func(ctx context.Context, scanID uuid.UUID, tools []string) ([]domain.ScanResult, error) {
			return []domain.ScanResult{}, nil
		},
	}

	scanService := services.NewScanService(
		&mock.MockVulnerabilityRepo{},
		&mock.MockScanRepo{},
		&mock.MockHostRepo{},
		mockScaResultsRepo,
	)
	results, errGetScan := scanService.GetInformationGatheredResults(context.Background(), uuid.New())
	assert.NoError(t, errGetScan)
	assert.Empty(t, results)
}

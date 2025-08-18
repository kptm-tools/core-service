package services_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	mocks "github.com/kptm-tools/core-service/pkg/mocks/storage"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/stretchr/testify/assert"
)

func Test_InsertScanScheduling_Success(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockCreateScanSchedule: func(ctx context.Context, ss domain.ScanSchedule) (*domain.ScanSchedule, error) {
				return nil, nil
			},
		},
	)
	_, errInsert := scanScheduleService.CreateScanSchedule(context.Background(), uuid.Nil, time.Now().UTC(), nil, uuid.Nil)
	assert.NoError(t, errInsert)
}

func Test_InsertScanScheduling_Error(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockCreateScanSchedule: func(ctx context.Context, ss domain.ScanSchedule) (*domain.ScanSchedule, error) {
				return nil, errors.New("failed to insert scan scheduling")
			},
		},
	)
	_, errInsert := scanScheduleService.CreateScanSchedule(context.Background(), uuid.Nil, time.Now().UTC(), nil, uuid.Nil)
	assert.Error(t, errInsert)
	assert.Contains(t, errInsert.Error(), "failed to insert scan scheduling")
}

func Test_DeleteScanScheduleByID_Error(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockDeleteScanScheduleByID: func(ctx context.Context, scanScheduleID int32) (bool, error) {
				return false, fmt.Errorf("failed to delete scan schedule")
			},
		},
	)
	isDeleted, errDelete := scanScheduleService.DeleteScanScheduleByID(context.Background(), 1)
	assert.Error(t, errDelete)
	assert.Equal(t, false, isDeleted)
}

func Test_DeleteScanScheduleByID_Success(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockDeleteScanScheduleByID: func(ctx context.Context, scanScheduleID int32) (bool, error) {
				return true, nil
			},
		},
	)
	isDeleted, errDelete := scanScheduleService.DeleteScanScheduleByID(context.Background(), 1)
	assert.NoError(t, errDelete)
	assert.True(t, isDeleted)
}

func Test_GetScanSchedules_Error(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockGetScanSchedulesByTenantID: func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error) {
				return nil, fmt.Errorf("failed to get scan schedules")
			},
		},
	)
	scanSchedules, errGet := scanScheduleService.GetScanSchedulesByTenantID(context.Background(), uuid.Nil)
	assert.Error(t, errGet)
	assert.Nil(t, scanSchedules)
}

func Test_GetScanSchedules_Success_NoRows(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockGetScanSchedulesByTenantID: func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error) {
				return []domain.ScanScheduleSummary{}, nil
			},
		},
	)
	scanSchedules, errGet := scanScheduleService.GetScanSchedulesByTenantID(context.Background(), uuid.Nil)
	assert.NoError(t, errGet)
	assert.Empty(t, scanSchedules)
}

func Test_GetScanSchedules_Success(t *testing.T) {
	sampleSchedules := []domain.ScanScheduleSummary{
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
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockGetScanSchedulesByTenantID: func(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanScheduleSummary, error) {
				return sampleSchedules, nil
			},
		},
	)

	scanSchedules, errGet := scanScheduleService.GetScanSchedulesByTenantID(context.Background(), uuid.Nil)
	assert.NoError(t, errGet)
	assert.Len(t, scanSchedules, 2)
}

func Test_PatchScanSchedule_Error_Disable(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{},
		&mocks.MockScanScheduleRepo{
			MockDisableJob: func(ctx context.Context, i int32, b bool) error {
				return errors.New("failed to unregister job")
			},
		},
	)

	errPatch := scanScheduleService.PatchScanSchedule(context.Background(), 1, nil, time.Now(), uuid.Nil, uuid.Nil, uuid.Nil)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to unregister job")
}

func Test_PatchScanSchedule_Error_CreateScan(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{
			MockCreateScan: func(ctx context.Context, s domain.Scan) (*domain.Scan, error) {
				return nil, errors.New("failed to create scan")
			},
		},
		&mocks.MockScanScheduleRepo{
			MockCreateScanSchedule: func(ctx context.Context, ss domain.ScanSchedule) (*domain.ScanSchedule, error) {
				return nil, nil
			},
			MockDisableJob: func(ctx context.Context, i int32, b bool) error {
				return nil
			},
		},
	)

	errPatch := scanScheduleService.PatchScanSchedule(context.Background(), 1, nil, time.Now(), uuid.Nil, uuid.Nil, uuid.Nil)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to create scan")
}

func Test_PatchScanSchedule_Error_EnableJob(t *testing.T) {
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{
			MockCreateScan: func(ctx context.Context, s domain.Scan) (*domain.Scan, error) {
				return nil, nil
			},
		},
		&mocks.MockScanScheduleRepo{
			MockCreateScanSchedule: func(ctx context.Context, ss domain.ScanSchedule) (*domain.ScanSchedule, error) {
				return nil, nil
			},

			MockEnableJob: func(ctx context.Context, s string, b bool, i int32) error {
				return errors.New("failed to enable job")
			},
			MockDisableJob: func(ctx context.Context, i int32, b bool) error {
				return nil
			},
		},
	)
	errPatch := scanScheduleService.PatchScanSchedule(context.Background(), 1, nil, time.Now(), uuid.Nil, uuid.Nil, uuid.Nil)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to enable job")
}

func Test_PatchScanSchedule_Error_Patch(t *testing.T) {
	now := time.Now()
	scanData := domain.NewScan(uuid.Nil, uuid.Nil, uuid.Nil, &now)
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{
			MockCreateScan: func(ctx context.Context, s domain.Scan) (*domain.Scan, error) {
				return scanData, nil
			},
		},
		&mocks.MockScanScheduleRepo{
			MockPatchScanScheduleByID: func(ctx context.Context, i1 int32, u uuid.UUID, s1 string, b bool, s2 string, i2 int32, t time.Time) error {
				return errors.New("failed to patch scan schedule")
			},
			MockDisableJob: func(ctx context.Context, i int32, b bool) error {
				return nil
			},
			MockEnableJob: func(ctx context.Context, s string, b bool, i int32) error {
				return nil
			},
		},
	)
	errPatch := scanScheduleService.PatchScanSchedule(context.Background(), 1, nil, time.Now(), uuid.Nil, uuid.Nil, uuid.Nil)
	assert.Error(t, errPatch)
	assert.Contains(t, errPatch.Error(), "failed to patch scan schedule")
}

func Test_PatchScanSchedule_Success(t *testing.T) {
	now := time.Now()
	scanData := domain.NewScan(uuid.Nil, uuid.Nil, uuid.Nil, &now)
	scanScheduleService := services.NewScanScheduleService(
		&mocks.MockTxManager{
			MockDoInTx: func(ctx context.Context, tf interfaces.TxFunc) error { return nil },
		},
		&mocks.MockScanRepo{
			MockCreateScan: func(ctx context.Context, s domain.Scan) (*domain.Scan, error) {
				return scanData, nil
			},
		},
		&mocks.MockScanScheduleRepo{
			MockPatchScanScheduleByID: func(ctx context.Context, i1 int32, u uuid.UUID, s1 string, b bool, s2 string, i2 int32, t time.Time) error {
				return nil
			},
			MockDisableJob: func(ctx context.Context, i int32, b bool) error {
				return nil
			},
			MockEnableJob: func(ctx context.Context, s string, b bool, i int32) error {
				return nil
			},
		},
	)

	errPatch := scanScheduleService.PatchScanSchedule(context.Background(), 1, nil, time.Now(), uuid.Nil, uuid.Nil, uuid.Nil)
	assert.NoError(t, errPatch)
}

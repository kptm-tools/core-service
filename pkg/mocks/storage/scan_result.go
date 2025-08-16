package mockstorage

import (
	"context"
	"fmt"
	"github.com/google/uuid"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockScanResultRepo struct {
	MockCreateScanResult       func(context.Context, domain.ScanResult) error
	MockGetScanResultsByScanID func(ctx context.Context, scanID uuid.UUID, tools []string) ([]domain.ScanResult, error)
}

var _ interfaces.ScanResultRepository = (*MockScanResultRepo)(nil)

func (m *MockScanResultRepo) CreateScanResult(ctx context.Context, result domain.ScanResult) error {
	if m.MockCreateScanResult != nil {
		return m.MockCreateScanResult(ctx, result)
	}
	panic(fmt.Sprintf("MockScanResultRepo: method CreateScanResult called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockScanResultRepo) GetScanResultsByScanID(ctx context.Context, scanID uuid.UUID, tools []string) ([]domain.ScanResult, error) {
	if m.MockGetScanResultsByScanID != nil {
		return m.MockGetScanResultsByScanID(ctx, scanID, tools)
	}
	panic(fmt.Sprintf("MockScanResultRepo: method GetScanResultsByScanID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

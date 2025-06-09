package mockstorage

import (
	"context"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockScanResultRepo struct {
	MockCreateScanResult func(context.Context, domain.ScanResult) error
}

var _ interfaces.ScanResultRepository = (*MockScanResultRepo)(nil)

func (m *MockScanResultRepo) CreateScanResult(ctx context.Context, result domain.ScanResult) error {
	if m.MockCreateScanResult != nil {
		return m.MockCreateScanResult(ctx, result)
	}
	panic(fmt.Sprintf("MockScanResultRepo: method CreateScanResult called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

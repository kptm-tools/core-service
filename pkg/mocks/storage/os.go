package mockstorage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockOSRepo struct {
	MockCreateOS  func(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, osData tools.OSData) (*domain.OperatingSystem, error)
	MockGetOSByID func(ctx context.Context, osID int32) (*domain.OperatingSystem, error)
}

var _ interfaces.OSRepository = (*MockOSRepo)(nil)

func (m *MockOSRepo) CreateOS(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, osData tools.OSData) (*domain.OperatingSystem, error) {
	if m.MockCreateOS != nil {
		return m.MockCreateOS(ctx, hostID, scanID, osData)
	}
	panic(fmt.Sprintf("MockOSRepo: method CreateOS called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockOSRepo) GetOSByID(ctx context.Context, osID int32) (*domain.OperatingSystem, error) {
	if m.MockGetOSByID != nil {
		return m.MockGetOSByID(ctx, osID)
	}
	panic(fmt.Sprintf("MockOSRepo: method GetOSByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

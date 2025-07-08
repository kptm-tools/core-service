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

type MockServiceRepo struct {
	MockCreateOrUpdateService            func(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, portData tools.PortData) (*domain.Service, error)
	MockGetServiceByID                   func(context.Context, int32) (*domain.Service, error)
	MockGetServiceByScanHostPortProtocol func(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, port int32, protocol string) (*domain.Service, error)
}

var _ interfaces.ServiceRepository = (*MockServiceRepo)(nil)

func (m *MockServiceRepo) CreateOrUpdateService(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, portData tools.PortData) (*domain.Service, error) {
	if m.MockCreateOrUpdateService != nil {
		return m.MockCreateOrUpdateService(ctx, hostID, scanID, portData)
	}
	panic(fmt.Sprintf("MockServiceRepo: method CreateOrUpdateService called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockServiceRepo) GetServiceByID(ctx context.Context, id int32) (*domain.Service, error) {
	if m.MockGetServiceByID != nil {
		return m.MockGetServiceByID(ctx, id)
	}
	panic(fmt.Sprintf("MockServiceRepo: method GetServiceByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockServiceRepo) GetServiceByScanHostPortProtocol(ctx context.Context, hostID uuid.UUID, scanID uuid.UUID, port int32, protocol string) (*domain.Service, error) {
	if m.MockGetServiceByScanHostPortProtocol != nil {
		return m.MockGetServiceByScanHostPortProtocol(ctx, hostID, scanID, port, protocol)
	}
	panic(fmt.Sprintf("MockServiceRepo: method GetServiceByScanHostPortProtocol called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

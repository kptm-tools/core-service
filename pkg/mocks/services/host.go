package mockservices

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/testutil"
)

type MockHostService struct {
	MockCreateHost         func(context.Context, *domain.Host) (*domain.Host, error)
	MockGetHostsByTenantID func(ctx context.Context, tenantID uuid.UUID) ([]*domain.Host, error)
	MockGetHostByID        func(ctx context.Context, ID uuid.UUID) (*domain.Host, error)
	MockGetDomainIPValues  func(string) (*domain.DomainIPResult, error)
	MockDeleteHostByID     func(ctx context.Context, ID uuid.UUID) (bool, error)
	MockPatchHostByID      func(context.Context, *domain.Host) (*domain.Host, error)
	MockValidateHost       func(context.Context, string) error
	MockValidateAlias      func(context.Context, string) error
}

var _ interfaces.IHostService = (*MockHostService)(nil)

func (m *MockHostService) CreateHost(ctx context.Context, host *domain.Host) (*domain.Host, error) {
	if m.MockCreateHost != nil {
		return m.MockCreateHost(ctx, host)
	}
	panic(fmt.Sprintf("MockHostService: method CreateHost called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockHostService) GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*domain.Host, error) {
	if m.MockGetHostsByTenantID != nil {
		return m.MockGetHostsByTenantID(ctx, tenantID)
	}
	panic(fmt.Sprintf("MockHostService: method GetHostsByTenantID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockHostService) GetHostByID(ctx context.Context, ID uuid.UUID) (*domain.Host, error) {
	if m.MockGetHostByID != nil {
		return m.MockGetHostByID(ctx, ID)
	}
	panic(fmt.Sprintf("MockHostService: method GetHostByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockHostService) GetDomainIPValues(s string) (*domain.DomainIPResult, error) {
	if m.MockGetDomainIPValues != nil {
		return m.MockGetDomainIPValues(s)
	}
	panic("MockHostService: method GetDomainIPValues called but not implemented for test")
}

func (m *MockHostService) DeleteHostByID(ctx context.Context, ID uuid.UUID) (bool, error) {
	if m.MockDeleteHostByID != nil {
		return m.MockDeleteHostByID(ctx, ID)
	}
	panic(fmt.Sprintf("MockHostService: method DeleteHostByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockHostService) PatchHostByID(ctx context.Context, host *domain.Host) (*domain.Host, error) {
	if m.MockPatchHostByID != nil {
		return m.MockPatchHostByID(ctx, host)
	}
	panic(fmt.Sprintf("MockHostService: method PatchHostByID called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockHostService) ValidateHost(ctx context.Context, s string) error {
	if m.MockValidateHost != nil {
		return m.MockValidateHost(ctx, s)
	}
	panic(fmt.Sprintf("MockHostService: method ValidateHost called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

func (m *MockHostService) ValidateAlias(ctx context.Context, s string) error {
	if m.MockValidateAlias != nil {
		return m.MockValidateAlias(ctx, s)
	}
	panic(fmt.Sprintf("MockHostService: method ValidateAlias called but not implemented for test: %s", ctx.Value(testutil.TestNameKey)))
}

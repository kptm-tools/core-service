package mockstorage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type MockHostRepo struct {
	MockCreateHost         func(context.Context, *domain.Host) (*domain.Host, error)
	MockGetHostByID        func(context.Context, uuid.UUID) (*domain.Host, error)
	MockGetHostsByTenantID func(ctx context.Context, tenantID uuid.UUID, hostsIDFilter []uuid.UUID) ([]*domain.Host, error)
	MockDeleteHostByID     func(context.Context, uuid.UUID) (bool, error)
	MockPatchHostByID      func(context.Context, domain.Host) (*domain.Host, error)
	MockAliasExists        func(context.Context, string) (bool, error)
}

var _ interfaces.HostRepository = (*MockHostRepo)(nil)

func (m *MockHostRepo) CreateHost(ctx context.Context, host *domain.Host) (*domain.Host, error) {
	if m.MockCreateHost != nil {
		return m.MockCreateHost(ctx, host)
	}
	panic(fmt.Sprintf("MockHostRepo: method CreateHost called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockHostRepo) GetHostByID(ctx context.Context, id uuid.UUID) (*domain.Host, error) {
	if m.MockGetHostByID != nil {
		return m.MockGetHostByID(ctx, id)
	}
	panic(fmt.Sprintf("MockHostRepo: method GetHostByID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockHostRepo) GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID, hostsIDFilter []uuid.UUID) ([]*domain.Host, error) {
	if m.MockGetHostsByTenantID != nil {
		return m.MockGetHostsByTenantID(ctx, tenantID, hostsIDFilter)
	}
	panic(fmt.Sprintf("MockHostRepo: method GetHostsByTenantID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockHostRepo) DeleteHostByID(ctx context.Context, id uuid.UUID) (bool, error) {
	if m.MockDeleteHostByID != nil {
		return m.MockDeleteHostByID(ctx, id)
	}
	panic(fmt.Sprintf("MockHostRepo: method DeleteHostByID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockHostRepo) PatchHostByID(ctx context.Context, host domain.Host) (*domain.Host, error) {
	if m.MockPatchHostByID != nil {
		return m.MockPatchHostByID(ctx, host)
	}
	panic(fmt.Sprintf("MockHostRepo: method PatchHostByID called but not implemented for test: %s", ctx.Value("test_name")))
}

func (m *MockHostRepo) AliasExists(ctx context.Context, alias string) (bool, error) {
	if m.MockAliasExists != nil {
		return m.MockAliasExists(ctx, alias)
	}
	panic(fmt.Sprintf("MockHostRepo: method AliasExists called but not implemented for test: %s", ctx.Value("test_name")))
}

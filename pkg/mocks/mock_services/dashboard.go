package mock_services

import "github.com/kptm-tools/core-service/pkg/domain"

type MockTenantService struct {
	MockCreateTenant           func(*domain.Tenant) (*domain.Tenant, error)
	MockGetTenants             func() ([]*domain.Tenant, error)
	MockGetTenantDashboardData func(string) (*domain.TenantDashboardData, error)
}

func (m *MockTenantService) CreateTenant(tenant *domain.Tenant) (*domain.Tenant, error) {
	if m.MockCreateTenant != nil {
		return m.MockCreateTenant(tenant)
	}
	return nil, nil
}

func (m MockTenantService) GetTenants() ([]*domain.Tenant, error) {
	if m.MockGetTenants != nil {
		return m.MockGetTenants()
	}
	return nil, nil
}

func (m *MockTenantService) GetTenantDashboardData(tenantID string) (*domain.TenantDashboardData, error) {
	if m.MockGetTenantDashboardData != nil {
		return m.MockGetTenantDashboardData(tenantID)
	}
	return nil, nil
}

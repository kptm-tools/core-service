package mock_services

import "github.com/kptm-tools/core-service/pkg/domain"

type MockHostService struct {
	MockCreateHost             func(host *domain.Host) (*domain.Host, error)
	MockGetTenantDashboardData func(string) (*domain.TenantDashboardData, error)
}

func (m *MockHostService) CreateHost(host *domain.Host) (*domain.Host, error) {
	if m.MockCreateHost != nil {
		return m.MockCreateHost(host)
	}
	return host, nil
}

func (m *MockHostService) GetHostsByTenantID(tenantID string) ([]*domain.Host, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) GetHostByID(ID int) (*domain.Host, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) GetHostNameFromIP(s string) ([]string, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) GetDomainIPValues(s string) (*domain.DomainIPResult, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) DeleteHostByID(ID int) (bool, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) PatchHostByID(host *domain.Host) (*domain.Host, error) {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) ValidateHost(s string) error {
	// TODO implement me
	panic("implement me")
}

func (m *MockHostService) ValidateAlias(s string) error {
	// TODO implement me
	panic("implement me")
}

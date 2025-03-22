package interfaces

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITenantService interface {
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	GetTenantDashboardData(tenantID string, trendsTimePeriodFilter domain.TimePeriodFilter, trendsSeverityFilter []string, hostsFilter []int) (*domain.TenantDashboardData, error)
}

type ITenantHandlers interface {
	// CreateTenant(w http.ResponseWriter, req *http.Request) error
	GetTenants(w http.ResponseWriter, req *http.Request) error
	GetDashboard(w http.ResponseWriter, req *http.Request) error
}

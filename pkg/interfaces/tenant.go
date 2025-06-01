package interfaces

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type ITenantService interface {
	CreateTenant(*domain.Tenant) (*domain.Tenant, error)
	GetTenants() ([]*domain.Tenant, error)
	GetTenantDashboardData(ctx context.Context, tenantID uuid.UUID, trendsTimePeriodFilter domain.TimePeriodFilter, trendsSeverityFilter []string, hostsFilter []uuid.UUID) (*domain.TenantDashboardData, error)
}

type ITenantHandlers interface {
	// CreateTenant(w http.ResponseWriter, req *http.Request) error
	GetTenants(w http.ResponseWriter, req *http.Request) error
	GetDashboard(w http.ResponseWriter, req *http.Request) error
}

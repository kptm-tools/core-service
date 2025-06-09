package interfaces

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IDashboardService interface {
	GetTenantDashboardData(ctx context.Context, tenantID uuid.UUID, trendsTimePeriodFilter domain.TimePeriodFilter, trendsSeverityFilter []string, hostsFilter []uuid.UUID) (*domain.TenantDashboardData, error)
}

type IDashboardHandlers interface {
	GetDashboard(w http.ResponseWriter, req *http.Request) error
}

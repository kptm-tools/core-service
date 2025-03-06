package handlers

import (
	"log/slog"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type TenantHandlers struct {
	tenantService interfaces.ITenantService
}

var _ interfaces.ITenantHandlers = (*TenantHandlers)(nil)

func NewTenantHandlers(tenantService interfaces.ITenantService) *TenantHandlers {
	return &TenantHandlers{
		tenantService: tenantService,
	}
}

func (h *TenantHandlers) GetTenants(w http.ResponseWriter, req *http.Request) error {
	tenants, err := h.tenantService.GetTenants()
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusOK, tenants)
}

func (h *TenantHandlers) GetDashboard(w http.ResponseWriter, req *http.Request) error {
	tenantIDStr := req.Context().Value(middleware.ContextTenantID).(string)

	tenantDasboardData, err := h.tenantService.GetTenantDashboardData(tenantIDStr)
	if err != nil {
		slog.Error("Error getting tenant dashboard data",
			slog.String("tenant_id", tenantIDStr),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	return api.WriteJSON(w, http.StatusUnprocessableEntity, tenantDasboardData)
}

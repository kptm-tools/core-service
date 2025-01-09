package handlers

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
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

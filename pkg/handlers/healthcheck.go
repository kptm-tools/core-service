package handlers

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type HealthcheckHandlers struct {
	healthcheckService interfaces.IHealthcheckService
}

var _ interfaces.IHealthcheckHandlers = (*HealthcheckHandlers)(nil)

func NewHealthcheckHandlers(healthcheckService interfaces.IHealthcheckService) *HealthcheckHandlers {
	return &HealthcheckHandlers{
		healthcheckService: healthcheckService,
	}
}

func (h *HealthcheckHandlers) Healthcheck(w http.ResponseWriter, req *http.Request) error {
	status := h.healthcheckService.CheckHealth()

	if !status.OverallHealthy {
		return api.WriteJSON(w, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
	}

	return api.WriteJSON(w, http.StatusOK, "Healthcheck - OK")
}

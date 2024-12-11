package handlers

import (
	"errors"
	"log"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/services"
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

	if err := h.healthcheckService.CheckHealth(); err != nil {
		log.Println(err.Error())
		status := http.StatusInternalServerError
		if errors.Is(err, services.ErrorUnhealthy) {
			status = http.StatusServiceUnavailable
		}
		return api.WriteJSON(w, status, http.StatusText(status))
	}

	return api.WriteJSON(w, http.StatusOK, "Healthcheck - OK")
}

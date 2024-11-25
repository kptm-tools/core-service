package handlers

import (
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type TargetHandlers struct {
	targetService interfaces.ITargetService
}

var _ interfaces.ITargetHandlers = (*TargetHandlers)(nil)

func NewTargetHandlers(targetService interfaces.ITargetService) *TargetHandlers {
	return &TargetHandlers{
		targetService: targetService,
	}
}

func (h *TargetHandlers) GetTargetsByTenantID(w http.ResponseWriter, req *http.Request) error {

	targets, err := h.targetService.GetTargetsByTenantID("9ca3bc6c-4b78-472d-9194-62bb75d3e9fa")

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusOK, targets)
}

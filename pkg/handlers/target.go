package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/domain"
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

func (h *TargetHandlers) CreateTarget(w http.ResponseWriter, req *http.Request) error {

	createTargetRequest := new(CreateTargetRequest)

	if err := json.NewDecoder(req.Body).Decode(createTargetRequest); err != nil {
		return err
	}

	// Validate the Target Type

	// if !domain.IsValidTargetValue(createTargetRequest.Value) {
	// 	return api.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid target value"})
	// }

	// Parse the type
	t := domain.ParseTargetType(createTargetRequest.Value)

	target := domain.NewTarget(createTargetRequest.Value, t, createTargetRequest.TenantID, createTargetRequest.OperatorID)

	target, err := h.targetService.CreateTarget(target)

	if err != nil {

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, target)
}

func (h *TargetHandlers) GetTargetsByTenantID(w http.ResponseWriter, req *http.Request) error {

	getTargetByTenantIDRequest := new(GetTargetByTenantIDRequest)

	if err := json.NewDecoder(req.Body).Decode(getTargetByTenantIDRequest); err != nil {
		return err
	}

	targets, err := h.targetService.GetTargetsByTenantID(getTargetByTenantIDRequest.TenantID)

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusOK, targets)
}

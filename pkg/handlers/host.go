package handlers

import (
	"errors"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type HostHandlers struct {
	hostService interfaces.IHostService
}

var _ interfaces.IHostHandlers = (*HostHandlers)(nil)

func NewHostHandlers(hostService interfaces.IHostService) *HostHandlers {
	return &HostHandlers{
		hostService: hostService,
	}
}

func (h *HostHandlers) CreateHost(w http.ResponseWriter, req *http.Request) error {

	createHostRequest := new(CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	// Validate the Host Type

	// if !domain.IsValidHostValue(createHostRequest.Value) {
	// 	return api.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid host value"})
	// }

	// Parse the type
	t := domain.ParseHostType(createHostRequest.Value)

	host := domain.NewHost(createHostRequest.Value, t, createHostRequest.TenantID, createHostRequest.OperatorID, createHostRequest.Name)

	host, err := h.hostService.CreateHost(host)

	if err != nil {

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, host)
}

func (h *HostHandlers) GetHostsByTenantID(w http.ResponseWriter, req *http.Request) error {

	getHostByTenantIDRequest := new(GetHostByTenantIDRequest)

	if err := decodeJSONBody(w, req, getHostByTenantIDRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	hosts, err := h.hostService.GetHostsByTenantID(getHostByTenantIDRequest.TenantID)

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusOK, hosts)
}

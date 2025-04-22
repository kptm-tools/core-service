package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/ws/report/dto"

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
	createHostRequest := new(dto.CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	host, err := h.constructHostForDB(createHostRequest, req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	host, err = h.hostService.CreateHost(host)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, constructResponse(host))
}

func (h *HostHandlers) GetHosts(w http.ResponseWriter, req *http.Request) error {
	tenantID := req.Context().Value(middleware.ContextTenantID).(string)

	hosts, err := h.hostService.GetHostsByTenantID(tenantID)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	hostsResponse := []*domain.HostResponse{}
	for _, host := range hosts {
		hostsResponse = append(hostsResponse, constructResponse(host))
	}

	return api.WriteJSON(w, http.StatusOK, hostsResponse)
}

func (h *HostHandlers) GetHostByID(w http.ResponseWriter, req *http.Request) error {
	id, err := GetID(req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	host, err := h.hostService.GetHostByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			statusCode := http.StatusNotFound
			return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusOK, constructResponse(host))
}

func (h *HostHandlers) PatchHostByID(w http.ResponseWriter, req *http.Request) error {
	id, err := GetID(req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	createHostRequest := new(dto.CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	hostToDB, err := h.constructHostForDB(createHostRequest, req)
	if err != nil {
		return err
	}
	hostToDB.ID = id
	host, err := h.hostService.PatchHostByID(hostToDB)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			statusCode := http.StatusNotFound
			return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, constructResponse(host))
}

func (h *HostHandlers) DeleteHostByID(w http.ResponseWriter, req *http.Request) error {
	id, err := GetID(req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	isDeleted, err := h.hostService.DeleteHostByID(id)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	result := make(map[string]string)
	if isDeleted {
		result["deleted"] = "true"
	} else {
		result["deleted"] = "false"
	}
	return api.WriteJSON(w, http.StatusOK, result)
}

func (h *HostHandlers) ValidateHost(w http.ResponseWriter, req *http.Request) error {
	validateHostRequest := new(dto.ValidateHostRequest)

	if err := decodeJSONBody(w, req, validateHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	if err := h.hostService.ValidateHost(validateHostRequest.Value); err != nil {
		if errors.Is(err, services.ErrInvalidHostValue) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		} else if errors.Is(err, services.ErrHostUnhealthy) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusOK, http.StatusText(http.StatusOK))
}

func (h *HostHandlers) constructHostForDB(createHostRequest *dto.CreateHostRequest, req *http.Request) (*domain.Host, error) {
	result, err := h.hostService.GetDomainIPValues(createHostRequest.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain and IP values: %w", err)
	}
	tenantID := req.Context().Value(middleware.ContextTenantID)
	operatorID := req.Context().Value(middleware.ContextUserID)

	host := domain.NewHost(
		result.Domain,
		result.IP,
		tenantID.(string),
		operatorID.(string),
		createHostRequest.Name,
		createHostRequest.Credentials,
		createHostRequest.Rapporteurs)
	return host, nil
}

func constructResponse(host *domain.Host) *domain.HostResponse {
	hostResponse := new(domain.HostResponse)
	hostResponse.Name = host.Name
	hostResponse.CreatedAt = host.CreatedAt
	hostResponse.UpdatedAt = host.UpdatedAt
	hostResponse.ID = strconv.Itoa(host.ID)
	hostResponse.Domain = host.Domain
	hostResponse.IP = host.IP
	hostResponse.Rapporteurs = host.Rapporteurs
	hostResponse.Credentials = host.Credentials
	return hostResponse
}

func (h *HostHandlers) ValidateAlias(w http.ResponseWriter, req *http.Request) error {
	validateAliasRequest := new(dto.ValidateAliasRequest)

	if err := decodeJSONBody(w, req, validateAliasRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	if err := h.hostService.ValidateAlias(validateAliasRequest.Hostname); err != nil {

		if errors.Is(err, services.ErrAliasTaken) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}
	return api.WriteJSON(w, http.StatusOK, http.StatusText(http.StatusOK))
}

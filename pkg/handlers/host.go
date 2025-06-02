package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"

	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/services"

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
	ctx := req.Context()
	createHostRequest := new(dto.CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	host, err := h.newDomainHostFromCreateRequest(createHostRequest, req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	host, err = h.hostService.CreateHost(ctx, host)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	response := dto.NewHostResponse(*host)

	return api.WriteJSON(w, http.StatusCreated, response)
}

func (h *HostHandlers) GetHosts(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	tenantID := req.Context().Value(middleware.ContextTenantID).(uuid.UUID)

	hosts, err := h.hostService.GetHostsByTenantID(ctx, tenantID)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	slog.Debug("Got hosts from service", slog.Int("len_hosts", len(hosts)))

	response := make([]dto.HostResponse, len(hosts))
	for i, host := range hosts {
		response[i] = dto.NewHostResponse(*host)
	}

	return api.WriteJSON(w, http.StatusOK, response)
}

func (h *HostHandlers) GetHostByID(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	id, err := GetUUID(req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	host, err := h.hostService.GetHostByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			statusCode := http.StatusNotFound
			return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	response := dto.NewHostResponse(*host)

	return api.WriteJSON(w, http.StatusOK, response)
}

func (h *HostHandlers) PatchHostByID(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	id, err := GetUUID(req)
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
	hostToDB, err := h.newDomainHostFromCreateRequest(createHostRequest, req)
	if err != nil {
		slog.Error("Failed to build new domain host from create host request", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}
	hostToDB.ID = id

	_, errGet := h.hostService.GetHostByID(ctx, hostToDB.ID)
	if errGet != nil {
		statusCode := http.StatusNotFound
		return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
	}

	// Get the value of the host, IP if it's an IP type, Hostname if it's a Domain/Subdomain
	if errValidation := h.hostService.ValidateHost(ctx, createHostRequest.Value); errValidation != nil {
		// Handle the case when the host value (the target) is not valid
		slog.Error("Failed to validate host value", slog.String("host_value", createHostRequest.Value), slog.Any("error", errValidation))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: errValidation.Error()})
	}
	if enums.IP.String() == createHostRequest.ValueType {
		hostToDB.Domain = ""
	}
	// Patch the host in the DB if everything's ok
	host, err := h.hostService.PatchHostByID(ctx, hostToDB)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			statusCode := http.StatusNotFound
			return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	response := dto.NewHostResponse(*host)

	return api.WriteJSON(w, http.StatusCreated, response)
}

func (h *HostHandlers) DeleteHostByID(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	id, err := GetUUID(req)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	isDeleted, err := h.hostService.DeleteHostByID(ctx, id)
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
	ctx := req.Context()
	validateHostRequest := new(dto.ValidateHostRequest)

	if err := decodeJSONBody(w, req, validateHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	if err := h.hostService.ValidateHost(ctx, validateHostRequest.Value); err != nil {
		if errors.Is(err, services.ErrInvalidHostValue) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		} else if errors.Is(err, services.ErrHostUnhealthy) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusOK, http.StatusText(http.StatusOK))
}

func (h *HostHandlers) newDomainHostFromCreateRequest(createHostRequest *dto.CreateHostRequest, req *http.Request) (*domain.Host, error) {
	ctx := req.Context()
	result, err := h.hostService.GetDomainIPValues(createHostRequest.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain and IP values: %w", err)
	}
	tenantID := ctx.Value(middleware.ContextTenantID).(uuid.UUID)
	operatorID := ctx.Value(middleware.ContextUserID).(uuid.UUID)

	host := domain.NewHost(
		result.Domain,
		result.IP,
		tenantID,
		operatorID,
		createHostRequest.Name,
		createHostRequest.Credentials,
		createHostRequest.Rapporteurs)
	return host, nil
}

func (h *HostHandlers) ValidateAlias(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	validateAliasRequest := new(dto.ValidateAliasRequest)

	if err := decodeJSONBody(w, req, validateAliasRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	if err := h.hostService.ValidateAlias(ctx, validateAliasRequest.Hostname); err != nil {

		if errors.Is(err, services.ErrAliasTaken) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}
	return api.WriteJSON(w, http.StatusOK, http.StatusText(http.StatusOK))
}

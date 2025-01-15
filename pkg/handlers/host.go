package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/kptm-tools/common/common/enums"
	cmmn "github.com/kptm-tools/common/common/events"
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

	createHostRequest := new(CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	host, err := constructHostForDB(createHostRequest, req, h)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	host, err = h.hostService.CreateHost(host)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, constructResponse(host))
}

func (h *HostHandlers) GetHostsByTenantIDAndUserID(w http.ResponseWriter, req *http.Request) error {

	tenantID := req.Context().Value(middleware.ContextTenantID).(string)
	userID := req.Context().Value(middleware.ContextUserID).(string)

	hosts, err := h.hostService.GetHostsByTenantIDAndUserID(tenantID, userID)

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

	createHostRequest := new(CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	hostToDB, err := constructHostForDB(createHostRequest, req, h)
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
	validateHostRequest := new(ValidateHostRequest)

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

	if err := h.hostService.ValidateAlias(validateHostRequest.Hostname); err != nil {

		if errors.Is(err, services.ErrAliasTaken) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusOK, http.StatusText(http.StatusOK))
}

func constructHostForDB(createHostRequest *CreateHostRequest, req *http.Request, h *HostHandlers) (*domain.Host, error) {
	domainVal, ipVal, err := getDomainIPValues(createHostRequest, h)
	if err != nil {
		return nil, err
	}
	tenantID := req.Context().Value(middleware.ContextTenantID)
	operatorID := req.Context().Value(middleware.ContextUserID)

	host := domain.NewHost(domainVal, ipVal, tenantID.(string), operatorID.(string), createHostRequest.Name, createHostRequest.Credentials, createHostRequest.Rapporteurs)
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

func getDomainIPValues(createHostRequest *CreateHostRequest, h *HostHandlers) (string, string, error) {
	domainValue := ""
	ipValue := ""
	if createHostRequest.ValueType == string(enums.Domain) {
		url := createHostRequest.Value
		if !cmmn.IsURL(url) {
			return "", "", fmt.Errorf("invalid url: %s", url)
		}

		domain, err := cmmn.ExtractDomain(url)
		if err != nil {
			return "", "", fmt.Errorf("failed to extract domain: %w", err)
		}
		ips, err := net.LookupIP(domain)
		if err != nil {
			return "", "", fmt.Errorf("error looking up IP of domain: %w", err)
		}
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				ipValue = ipv4.String()
				break
			}
		}
		return domain, ipValue, nil
	}

	if createHostRequest.ValueType == string(enums.IP) {
		normalizedURL := cmmn.NormalizeURL(createHostRequest.Value)

		ipValue = strings.Split(normalizedURL, "//")[1]
		domainValue = h.hostService.GetHostname(ipValue + ":443")
		return domainValue, ipValue, nil
	}

	return "", "", fmt.Errorf("invalid host type: must be one of `%s` or `%s`", string(enums.Domain), string(enums.IP))

}

package handlers

import (
	"encoding/json"
	"errors"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"net"
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

	host, err := h.hostService.CreateHost(constructHostForDB(createHostRequest, req, h))

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
	id := req.PathValue("id")
	host, err := h.hostService.GetHostByID(id)

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusOK, constructResponse(host))
}

func (h *HostHandlers) PatchHostByID(w http.ResponseWriter, req *http.Request) error {
	id := req.PathValue("id")

	createHostRequest := new(CreateHostRequest)

	if err := decodeJSONBody(w, req, createHostRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	domainVal, ipVal := getDomainIPValues(createHostRequest, h)
	dataCred, _ := json.Marshal(createHostRequest.Credentials)
	dataRapo, _ := json.Marshal(createHostRequest.Rapporteurs)
	host, err := h.hostService.PatchHostByID(id, domainVal, ipVal, createHostRequest.Name, dataCred, dataRapo)

	if err != nil {

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, constructResponse(host))
}

func (h *HostHandlers) DeleteHostByID(w http.ResponseWriter, req *http.Request) error {
	id := req.PathValue("id")
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

	validation, err := h.hostService.ValidateHost(validateHostRequest.Value)
	if err != nil {

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	return api.WriteJSON(w, http.StatusCreated, validation)
}

func constructHostForDB(createHostRequest *CreateHostRequest, req *http.Request, h *HostHandlers) *domain.Host {
	domainVal, ipVal := getDomainIPValues(createHostRequest, h)
	dataCred, _ := json.Marshal(createHostRequest.Credentials)
	dataRapo, _ := json.Marshal(createHostRequest.Rapporteurs)
	tenantID := req.Context().Value(middleware.ContextTenantID)
	operatorID := req.Context().Value(middleware.ContextUserID)

	host := domain.NewHost(domainVal, ipVal, tenantID.(string), operatorID.(string), createHostRequest.Name, dataCred, dataRapo)
	return host
}

func constructResponse(host *domain.Host) *domain.HostResponse {
	hostResponse := new(domain.HostResponse)
	hostResponse.Name = host.Name
	hostResponse.CreatedAt = host.CreatedAt
	hostResponse.ID = host.ID
	hostResponse.Domain = host.Domain
	hostResponse.Ip = host.Ip
	json.Unmarshal(host.Credentials, &hostResponse.Credentials)
	json.Unmarshal(host.Rapporteurs, &hostResponse.Rapporteurs)
	return hostResponse
}

func getDomainIPValues(createHostRequest *CreateHostRequest, h *HostHandlers) (string, string) {
	domainValue := ""
	ipValue := ""
	if createHostRequest.ValueType == "Domain" {
		domainValue = createHostRequest.Value
		ips, _ := net.LookupIP(domainValue)
		for _, ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				ipValue = ipv4.String()
				break
			}
		}
	} else {
		ipValue = createHostRequest.Value
		domainValue = h.hostService.GetHostname(ipValue + ":443")
	}
	return domainValue, ipValue
}

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/services"
)

type AuthHandlers struct {
	authService interfaces.IAuthService
}

var _ interfaces.IAuthHandlers = (*AuthHandlers)(nil)

func NewAuthHandlers(authService interfaces.IAuthService) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
	}
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	loginRequest := new(LoginRequest)

	if err := decodeJSONBody(w, r, loginRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	// Write the response from the service
	resp, err := h.authService.Login(loginRequest.LoginID, loginRequest.Password, loginRequest.ApplicationID)

	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, &resp)

}

func (h *AuthHandlers) RegisterTenant(w http.ResponseWriter, r *http.Request) error {

	registerTenantRequest := new(RegisterTenantRequest)

	if err := decodeJSONBody(w, r, registerTenantRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	t, err := h.authService.RegisterTenant(registerTenantRequest.Name)

	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusCreated, t)
}

func handleFusionAuthErrorResponse(w http.ResponseWriter, resp *http.Response) error {

	// If the response is a 400 error, standardize it into APIError
	if resp.StatusCode == http.StatusBadRequest {
		fusionAuthLoginErrorResponse := new(FusionAuthErrorResponse)
		if err := json.NewDecoder(resp.Body).Decode(fusionAuthLoginErrorResponse); err != nil {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}

		if len(fusionAuthLoginErrorResponse.GeneralErrors) > 0 {
			return api.WriteJSON(w, resp.StatusCode, api.APIError{Error: fusionAuthLoginErrorResponse.GeneralErrors[0].Message})
		}

		if len(fusionAuthLoginErrorResponse.FieldErrors) > 0 {
			for _, fieldErrors := range fusionAuthLoginErrorResponse.FieldErrors {
				if len(fieldErrors) > 0 {
					return api.WriteJSON(w, resp.StatusCode, api.APIError{Error: fieldErrors[0].Message})
				}
			}
		}
	}

	// Handle other error statuses in a generic way
	return api.WriteJSON(w, resp.StatusCode, resp.Body)
}

package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
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

	if err := json.NewDecoder(r.Body).Decode(loginRequest); err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Missing parameters"})
	}

	// Write the response from the service
	resp, err := h.authService.Login(loginRequest.LoginID, loginRequest.Password, loginRequest.ApplicationID)
	defer resp.Body.Close()

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	// Handle FusionAuth errors...
	if resp.StatusCode != http.StatusOK {
		return handleFusionAuthErrorResponse(w, resp)
	}

	// Read the response byes
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// Unmarshal into a map[string]string
	m, err := api.UnmarshalGenericJSON(responseBody)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, resp.StatusCode, m)

}

func (h *AuthHandlers) RegisterTenant(w http.ResponseWriter, r *http.Request) error {

	registerTenantRequest := new(RegisterTenantRequest)

	if err := decodeJSONBody(w, r, registerTenantRequest); err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
	}

	t, faErr, err := h.authService.RegisterTenant(registerTenantRequest.Name)

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}
	if faErr != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: faErr.Error()})
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

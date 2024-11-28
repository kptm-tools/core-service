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

	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	defer resp.Body.Close()

	// Read the response byes
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	// Unmarshal into a map[string]string
	m, err := api.UnmarshalGenericJSON(responseBody)
	if err != nil {
		return err
	}

	return api.WriteJSON(w, resp.StatusCode, m)

}

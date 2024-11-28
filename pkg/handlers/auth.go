package handlers

import (
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

	// Write the response from the service

	return api.WriteJSON(w, http.StatusOK, "Login Successful")
}

package handlers

import (
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

	t, u, err := h.authService.RegisterTenant(registerTenantRequest.Name)

	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusCreated, &RegisterTenantResponse{ApplicationID: t.ApplicationID, User: *u})
}

func (h *AuthHandlers) GetUser(w http.ResponseWriter, r *http.Request) error {
	id, err := GetUUID(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
	}

	user, err := h.authService.GetUserByID(id, nil)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, user)
}

func (h *AuthHandlers) ForgotPassword(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	forgotPasswordRequest := new(ForgotPasswordRequest)

	if err := decodeJSONBody(w, r, forgotPasswordRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	password, err := h.authService.ForgotPassword(forgotPasswordRequest.LoginID, forgotPasswordRequest.ApplicationID)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, password)
}

func (h *AuthHandlers) RegisterUser(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	registerUserRequest := new(RegisterUserRequest)

	if err := decodeJSONBody(w, r, registerUserRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	user, err := h.authService.RegisterUser(
		registerUserRequest.FirstName,
		registerUserRequest.LastName,
		registerUserRequest.Email,
		registerUserRequest.Password,
		registerUserRequest.ApplicationID,
		registerUserRequest.Roles)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, user)
}

func (h *AuthHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) error {
	id, err := GetUUID(r)
	tenantID, errTenant := GetTenantIDFromHeader(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
	}
	if errTenant != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: errTenant.Error()})
	}

	verifyEmailRequest := new(VerifyEmailRequest)

	if err := decodeJSONBody(w, r, verifyEmailRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	user, err := h.authService.VerifyEmail(verifyEmailRequest.VerificationID, id, tenantID)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, user)
}

func (h *AuthHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	changePasswordRequest := new(ChangePasswordRequest)

	if err := decodeJSONBody(w, r, changePasswordRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	changePassword, err := h.authService.ChangePassword(changePasswordRequest.ChangePasswordID, changePasswordRequest.Password, changePasswordRequest.LoginID, changePasswordRequest.ApplicationID)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, changePassword)
}

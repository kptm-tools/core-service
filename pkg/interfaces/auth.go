package interfaces

import (
	"net/http"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IAuthService interface {
	Login(email, password, applicationID string) (*fusionauth.LoginResponse, error)
	RegisterTenant(tenantName string) (*domain.Tenant, *domain.User, error)
	GetUserByID(userID string, tenantID *string) (*domain.User, error)
	ForgotPassword(email, applicationID string) (*fusionauth.ForgotPasswordResponse, error)
	RegisterUser() (*fusionauth.RegistrationResponse, error)
	SendEmailRegistration() (*fusionauth.SendResponse, error)
	VerifyEmail() (*fusionauth.BaseHTTPResponse, error)
}

type IAuthHandlers interface {
	Login(w http.ResponseWriter, req *http.Request) error
	RegisterTenant(w http.ResponseWriter, req *http.Request) error
	GetUser(w http.ResponseWriter, req *http.Request) error
	ForgotPassword(w http.ResponseWriter, req *http.Request) error
	RegisterUser(w http.ResponseWriter, req *http.Request) error
	VerifyEmail(w http.ResponseWriter, req *http.Request) error
}

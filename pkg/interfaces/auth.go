package interfaces

import (
	"net/http"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IAuthService interface {
	Login(email, password, applicationID string) (*fusionauth.LoginResponse, error)
	RegisterTenant(tenantName string) (*domain.Tenant, *domain.User, error)
}

type IAuthHandlers interface {
	Login(w http.ResponseWriter, req *http.Request) error
	RegisterTenant(w http.ResponseWriter, req *http.Request) error
}

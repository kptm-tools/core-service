package interfaces

import (
	"net/http"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/kptm-tools/core-service/pkg/domain"
)

type IAuthService interface {
	Login(email, password, applicationID string) (*http.Response, error)
	RegisterTenant(tenantName string) (*domain.Tenant, *fusionauth.Errors, error)
}

type IAuthHandlers interface {
	Login(w http.ResponseWriter, req *http.Request) error
	RegisterTenant(w http.ResponseWriter, req *http.Request) error
}

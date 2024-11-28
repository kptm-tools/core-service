package interfaces

import (
	"net/http"
)

type IAuthService interface {
	Login(email, password, applicationID string) error
}

type IAuthHandlers interface {
	Login(w http.ResponseWriter, req *http.Request) error
}
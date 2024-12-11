package interfaces

import (
	"net/http"
)

type IHealthcheckService interface {
	CheckHealth() error
}

type IHealthcheckHandlers interface {
	Healthcheck(w http.ResponseWriter, req *http.Request) error
}

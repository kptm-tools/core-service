package interfaces

import (
	"net/http"
)

type HealthStatus struct {
	DatabaseHealthy bool
	EventBusHealthy bool
	DatabaseError   string
	EventBusError   string
	OverallHealthy  bool
}

type IHealthcheckService interface {
	CheckHealth() *HealthStatus
}

type IHealthcheckHandlers interface {
	Healthcheck(w http.ResponseWriter, req *http.Request) error
}

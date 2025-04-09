package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"net/http"
)

type IHub interface {
	Run()
	Serve(w http.ResponseWriter, r *http.Request)
	Register(client IClient)
	Unregister(client IClient)
}

type IHubReport interface {
	IHub
	AddToRoom(scanID string)
	RemoveFromRoom(scanID string)
	GetRoomVulnerabilities(scanID string) []*domain.Vulnerability
}

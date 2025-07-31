package interfaces

import (
	"net/http"

	"github.com/kptm-tools/common/common/pkg/results/tools"
)

type IHub interface {
	Run()
	Serve(w http.ResponseWriter, r *http.Request)
	Register(client IClient)
	Unregister(client IClient)
}

type IScanHub interface {
	Run()
	Serve(w http.ResponseWriter, r *http.Request)
	Register(client IScanClient)
	Unregister(client IScanClient)
}

type IHubReport interface {
	IHub
	AddToRoom(scanID string)
	RemoveFromRoom(scanID string)
	GetRoomVulnerabilities(scanID string) []tools.Vulnerability
}

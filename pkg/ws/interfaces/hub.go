package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/domain"
	"net/http"
)

type IHub interface {
	Serve(w http.ResponseWriter, req *http.Request)
	AddClient(c *IClient)
	RemoveClient(c *IClient)
	RouteEvent(event domain.Event, c *IClient) error
}

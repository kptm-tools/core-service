package interfaces

import "net/http"

type IHubScanHandlers interface {
	Serve(w http.ResponseWriter, req *http.Request)
}

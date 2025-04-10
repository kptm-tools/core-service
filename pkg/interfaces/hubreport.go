package interfaces

import "net/http"

type IHubReportHandlers interface {
	Serve(w http.ResponseWriter, req *http.Request)
}

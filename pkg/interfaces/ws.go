package interfaces

import "net/http"

type IWsHandlers interface {
	Serve(w http.ResponseWriter, req *http.Request)
}

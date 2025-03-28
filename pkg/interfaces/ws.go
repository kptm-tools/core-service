package interfaces

import "net/http"

type IWsHandler interface {
	Serve(w http.ResponseWriter, req *http.Request)
}

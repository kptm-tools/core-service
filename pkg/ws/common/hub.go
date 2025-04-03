package common

import "net/http"

type IHub interface {
	Run()
	Serve(w http.ResponseWriter, r *http.Request)
	Register(client IClient)
	Unregister(client IClient)
}

package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type APIServer struct {
	listenAddr string

	targetHandler interfaces.ITargetHandlers
}

type APIError struct {
	Error string `json:"error"`
}

type APIFunc func(http.ResponseWriter, *http.Request) error

func NewAPIServer(listenAddr string, uHandlers interfaces.ITargetHandlers) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,

		targetHandler: uHandlers,
	}
}

func (s *APIServer) Init() error {
	router := http.NewServeMux()

	router.HandleFunc("/healthcheck", makeHTTPHandlerFunc(HandleHealthCheck))

	router.HandleFunc("/targets", makeHTTPHandlerFunc(s.targetHandler.GetTargetsByTenantID))

	server := http.Server{
		Addr: s.listenAddr,

		Handler: router,
	}

	log.Println("Server listening on port: ", s.listenAddr)

	return server.ListenAndServe()

}

func HandleHealthCheck(w http.ResponseWriter, r *http.Request) error {
	return WriteJSON(w, http.StatusOK, "Healthcheck - OK")
}

// This function wraps our APIFunc struct so we can handle errors gracefully
func makeHTTPHandlerFunc(f APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)

		if err != nil {
			WriteJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
		}

	}
}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)               // Write the status
	return json.NewEncoder(w).Encode(v) // To encode anything
}

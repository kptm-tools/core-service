package api

import (
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"runtime"
	"strings"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type APIServer struct {
	listenAddr string

	targetHandlers interfaces.ITargetHandlers
	authHandlers   interfaces.IAuthHandlers
	tenantHandlers interfaces.ITenantHandlers
}

type APIError struct {
	Error string `json:"error"`
}

type APIFunc func(http.ResponseWriter, *http.Request) error

func NewAPIServer(listenAddr string,
	tHandlers interfaces.ITargetHandlers,
	teHandlers interfaces.ITenantHandlers,
	aHandlers interfaces.IAuthHandlers,
) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,

		targetHandlers: tHandlers,
		authHandlers:   aHandlers,
		tenantHandlers: teHandlers,
	}
}

func (s *APIServer) Init() error {
	router := http.NewServeMux()

	router.HandleFunc("GET /healthcheck",
		makeHTTPHandlerFunc(HandleHealthCheck),
	)

	router.HandleFunc("POST /api/login", makeHTTPHandlerFunc(s.authHandlers.Login))

	router.HandleFunc("POST /targets", makeHTTPHandlerFunc(s.targetHandlers.CreateTarget))
	router.HandleFunc("GET /targets", makeHTTPHandlerFunc(s.targetHandlers.GetTargetsByTenantID))
	router.HandleFunc("GET /tenants", WithAuth(makeHTTPHandlerFunc(s.tenantHandlers.GetTenants), "tenants"))

	stack := middleware.CreateStack(
		middleware.Logging,
		middleware.CheckCORS,
	)

	server := http.Server{
		Addr: s.listenAddr,

		Handler: stack(router),
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

func UnmarshalGenericJSON(stringBytes []byte) (map[string]interface{}, error) {
	// This method receives an array of bytes and unmarshals them into a JSON
	m := map[string]interface{}{}

	if err := json.Unmarshal(stringBytes, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func GetFunctionName(i interface{}) string {
	strs := strings.Split(runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name(), ".")
	return strs[len(strs)-1]
}

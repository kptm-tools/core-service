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

	healthHandlers interfaces.IHealthcheckHandlers
	hostHandlers   interfaces.IHostHandlers
	authHandlers   interfaces.IAuthHandlers
	tenantHandlers interfaces.ITenantHandlers
	scanHandlers   interfaces.IScanHandlers
}

type APIError struct {
	Error string `json:"error"`
}

type APIFunc func(http.ResponseWriter, *http.Request) error

func NewAPIServer(
	listenAddr string,
	heHandlers interfaces.IHealthcheckHandlers,
	hoHandlers interfaces.IHostHandlers,
	teHandlers interfaces.ITenantHandlers,
	aHandlers interfaces.IAuthHandlers,
	sHandlers interfaces.IScanHandlers,
) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,

		healthHandlers: heHandlers,
		hostHandlers:   hoHandlers,
		authHandlers:   aHandlers,
		tenantHandlers: teHandlers,
		scanHandlers:   sHandlers,
	}
}

func (s *APIServer) Init() error {
	router := http.NewServeMux()

	router.HandleFunc("GET /healthcheck",
		makeHTTPHandlerFunc(s.healthHandlers.Healthcheck),
	)

	// Auth routes
	router.HandleFunc("POST /api/login", makeHTTPHandlerFunc(s.authHandlers.Login))
	router.HandleFunc("POST /api/forgot-password", makeHTTPHandlerFunc(s.authHandlers.ForgotPassword))
	router.HandleFunc("POST /api/change-password", makeHTTPHandlerFunc(s.authHandlers.ChangePassword))
	router.HandleFunc("POST /api/users", makeHTTPHandlerFunc(s.authHandlers.RegisterUser))
	router.HandleFunc("POST /api/users/{id}/verify-email", makeHTTPHandlerFunc(s.authHandlers.VerifyEmail))
	router.HandleFunc("POST /api/tenants", makeHTTPHandlerFunc(s.authHandlers.RegisterTenant))
	router.HandleFunc("GET /api/users/{id}", middleware.WithAuth(makeHTTPHandlerFunc(s.authHandlers.GetUser), "getUser"))

	router.HandleFunc("POST /api/hosts", middleware.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.CreateHost), "newHost"))
	router.HandleFunc("POST /api/hosts/validate", middleware.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.ValidateHost), "validateHost"))
	router.HandleFunc("GET /api/hosts", middleware.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.GetHostsByTenantIDAndUserID), "getHostsByTenantAndUser"))
	router.HandleFunc("GET /api/hosts/{id}", middleware.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.GetHostByID), "getHostByID"))
	router.HandleFunc("DELETE /api/hosts/{id}", middleware.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.DeleteHostByID), "deleteHostByID"))
	router.HandleFunc("PATCH /api/hosts/{id}", middleware.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.PatchHostByID), "patchHostByID"))
	router.HandleFunc("GET /tenants", middleware.WithAuth(makeHTTPHandlerFunc(s.tenantHandlers.GetTenants), "tenants"))

	router.HandleFunc("POST /api/scans", middleware.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.CreateScans), "createScans"))
	router.HandleFunc("POST /api/scans/{id}/cancel", middleware.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.CancelScanByID), "cancelScanByID"))

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

package api

import (
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"runtime"
	"strings"

	"github.com/kptm-tools/core-service/docs"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/middleware"

	"github.com/kptm-tools/core-service/pkg/interfaces"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

type APIServer struct {
	listenAddr string

	healthHandlers       interfaces.IHealthcheckHandlers
	hostHandlers         interfaces.IHostHandlers
	authHandlers         interfaces.IAuthHandlers
	tenantHandlers       interfaces.IDashboardHandlers
	scanHandlers         interfaces.IScanHandlers
	vulnHandlers         interfaces.IVulnerabilityHandlers
	scanScheduleHandlers interfaces.IScanScheduleHandlers
	scanHub              interfaces.IHub
	reportHub            interfaces.IHub
}

type APIError struct {
	Error string `json:"error"`
}

type APIFunc func(http.ResponseWriter, *http.Request) error

func NewAPIServer(
	listenAddr string,
	heHandlers interfaces.IHealthcheckHandlers,
	hoHandlers interfaces.IHostHandlers,
	teHandlers interfaces.IDashboardHandlers,
	aHandlers interfaces.IAuthHandlers,
	sHandlers interfaces.IScanHandlers,
	vHandlers interfaces.IVulnerabilityHandlers,
	ssHandlers interfaces.IScanScheduleHandlers,
	scanHub interfaces.IHub,
	reportHub interfaces.IHub,
) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,

		healthHandlers:       heHandlers,
		hostHandlers:         hoHandlers,
		authHandlers:         aHandlers,
		tenantHandlers:       teHandlers,
		scanHandlers:         sHandlers,
		vulnHandlers:         vHandlers,
		scanScheduleHandlers: ssHandlers,
		scanHub:              scanHub,
		reportHub:            reportHub,
	}
}

// Init configures and returns the HTTP server with all routes, middleware, and Swagger metadata.
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type “Bearer” followed by a space and your JWT token.
func (s *APIServer) Init() http.Server {
	c := config.LoadConfig()

	docs.SwaggerInfo.Title = "KPTM Core Service API"
	docs.SwaggerInfo.Description = "KPTM Core Service API documentation"
	docs.SwaggerInfo.Version = "1.0.0"
	docs.SwaggerInfo.Host = c.GetServerHost(false)
	docs.SwaggerInfo.BasePath = ""
	docs.SwaggerInfo.Schemes = c.GetScheme()

	router := http.NewServeMux()

	go s.scanHub.Run()
	go s.reportHub.Run()

	// swagger
	router.HandleFunc("/swagger/", httpSwagger.Handler(
		httpSwagger.URL(c.GetServerHost(true)+"/swagger/doc.json"),
	))

	router.HandleFunc("GET /healthcheck",
		makeHTTPHandlerFunc(s.healthHandlers.Healthcheck),
	)

	// Auth routes
	router.HandleFunc("POST /api/login", makeHTTPHandlerFunc(s.authHandlers.Login))
	router.HandleFunc("POST /api/forgot-password", makeHTTPHandlerFunc(s.authHandlers.ForgotPassword))
	router.HandleFunc("POST /api/change-password", makeHTTPHandlerFunc(s.authHandlers.ChangePassword))
	router.HandleFunc("POST /api/users", makeHTTPHandlerFunc(s.authHandlers.RegisterUser))
	router.HandleFunc("GET /api/users/verify", makeHTTPHandlerFunc(s.authHandlers.VerifyEmail))
	router.HandleFunc("GET /api/users/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.authHandlers.GetUser), domain.ActionUserGet))
	router.HandleFunc("GET /api/users/permissions", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.authHandlers.GetUserPermissions), domain.ActionUserGetPermissions))

	// Host routes
	router.HandleFunc("POST /api/hosts", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.CreateHost), domain.ActionHostCreate))
	router.HandleFunc("POST /api/hosts/validate-host", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.ValidateHost), domain.ActionHostValidate))
	router.HandleFunc("POST /api/hosts/validate-alias", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.ValidateAlias), domain.ActionHostValidateAlias))
	router.HandleFunc("GET /api/hosts", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.GetHosts), domain.ActionHostGetAll))
	router.HandleFunc("GET /api/hosts/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.GetHostByID), domain.ActionHostGetByID))
	router.HandleFunc("DELETE /api/hosts/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.DeleteHostByID), domain.ActionHostDeleteByID))
	router.HandleFunc("PATCH /api/hosts/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.hostHandlers.PatchHostByID), domain.ActionHostPatchByID))

	// Scan routes
	router.HandleFunc("POST /api/scans", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.CreateScan), domain.ActionScanCreate))
	router.HandleFunc("GET /api/scans/{id}/assets", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanAssetsByID), domain.ActionScanGetAssetsByID))
	router.HandleFunc("POST /api/scans/{id}/cancel", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.CancelScanByID), domain.ActionScanCancelByID))
	router.HandleFunc("GET /api/scans/{id}/insights", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanInsightsByID), domain.ActionScanGetInsightsByID))
	router.HandleFunc("GET /api/scans/{id}/vulnerabilities", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanVulnerabilities), domain.ActionScanGetVulnerabilitiesByID))
	router.HandleFunc("GET /api/scans/{id}/vulnerabilities/summary", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanVulnerabilitySummaryByID), domain.ActionScanGetVulnerabilitySummaryByID))
	router.HandleFunc("GET /api/scans/{id}/operating-system/vulnerabilities", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanOperatingSystemVulnerabilitiesByID), domain.ActionGetScanOperatingSystemVulnerabilitiesByID))
	router.HandleFunc("GET /api/scans/{id}/services/{service_id}/vulnerabilities", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanServicesVulnerabilitiesByServiceID), domain.ActionGetScanServicesVulnerabilitiesByServiceID))
	router.HandleFunc("GET /api/scans/{id}/information-gathered", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScanResultsByScanID), domain.ActionGetScanResultsByScanID))
	router.HandleFunc("GET /api/scorecard-trends", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetScoreCardTrends), domain.ActionScanGetScorecardTrends))

	// Scan schedules routes
	router.HandleFunc("DELETE /api/scan-schedules/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanScheduleHandlers.DeleteScanSchedule), domain.ActionScanScheduleDeleteByID))
	router.HandleFunc("PATCH /api/scan-schedules/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanScheduleHandlers.PatchScanSchedule), domain.ActionScanSchedulePatchByID))
	router.HandleFunc("GET /api/scan-schedules", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanScheduleHandlers.GetScanSchedules), domain.ActionScanScheduleGetAll))

	// Reports routes
	router.HandleFunc("GET /api/reports", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.scanHandlers.GetReports), domain.ActionReportGetAll))

	// Vulnerabilities routes
	router.HandleFunc("GET /api/vulnerabilities/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.vulnHandlers.GetVulnerability), domain.ActionVulnerabilityGet))
	router.HandleFunc("POST /api/vulnerabilities/{id}/comment", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.vulnHandlers.CreateVulnerabilityComment), domain.ActionVulnerabilityCreateComment))
	router.HandleFunc("PATCH /api/vulnerabilities/{id}/comment", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.vulnHandlers.PatchVulnerabilityComment), domain.ActionVulnerabilityPatchComment))
	router.HandleFunc("DELETE /api/vulnerabilities/{id}/comment", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.vulnHandlers.DeleteVulnerabilityComment), domain.ActionVulnerabilityDeleteComment))

	// Dashboard routes
	router.HandleFunc("GET /api/dashboard", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.tenantHandlers.GetDashboard), domain.ActionDashboardGet))

	// WebVulnerabilities routes
	router.HandleFunc("GET /api/web-vulnerabilities/{id}", s.authHandlers.WithAuth(makeHTTPHandlerFunc(s.vulnHandlers.GetWebVulnerabilityDetailsByID), domain.ActionWebVulnerabilityDetailGet))

	router.HandleFunc("/ws/scan", s.scanHub.Serve)
	router.HandleFunc("/ws/report/", s.reportHub.Serve)

	stack := middleware.CreateStack(
		middleware.Logging,
		middleware.CheckCORS,
	)
	log.Println("Server listening on port: ", s.listenAddr)
	return http.Server{
		Addr: s.listenAddr,

		Handler: stack(router),
	}
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

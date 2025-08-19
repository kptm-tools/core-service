package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	whoisparser "github.com/likexian/whois-parser"
	"strings"

	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
	hh "github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/stretchr/testify/assert"
)

func TestScanHandlers_GetScanAssetsByID(t *testing.T) {
	scanID := uuid.New()
	tests := []struct {
		name                string
		scanService         interfaces.IScanService
		scanScheduleService interfaces.IScanScheduleService
		vulnerability       interfaces.IVulnerabilityService
		hostService         interfaces.IHostService
		emailService        interfaces.IEmailService
		eventBus            events.EventBus
		r                   *http.Request
		wantStatus          int
	}{
		{
			name:                "Scan Bad Request → 400",
			scanService:         &mock_services.MockScanService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans//assets", nil)
				r.SetPathValue("id", "")
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Scan Not Completed → 409",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Failed"}, nil // not Completed
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/assets", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusConflict,
		},
		{
			name: "Scan Not Found → 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetScanAssetsByID: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error) {
					return []domain.ScanOSandServicesResult{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/assets", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusOK,
		},
		{
			name: "Scan Status Ok → 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetScanAssetsByID: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error) {
					return []domain.ScanOSandServicesResult{
						{
							AssetType:                 "os",
							ID:                        1,
							HostID:                    uuid.New(),
							ScanID:                    uuid.New(),
							Name:                      "Ubuntu Server",
							Version:                   "20.04",
							Family:                    "Linux",
							OsType:                    "Linux",
							Port:                      22,
							Protocol:                  "tcp",
							Fingerprint:               "OpenSSH 8.2",
							Cpe:                       "cpe:/o:ubuntu:ubuntu_linux:20.04",
							Product:                   "OpenSSH",
							Accuracy:                  95,
							PortState:                 "open",
							TotalVulnerabilitiesCount: 5,
							CriticalCount:             1,
							HighCount:                 2,
							MediumCount:               1,
							LowCount:                  1,
							NoneCount:                 0,
							UnknownCount:              0,
							CreatedAt:                 time.Now().AddDate(0, -1, 0),
							UpdatedAt:                 time.Now(),
						},
						{
							AssetType:                 "service",
							ID:                        2,
							HostID:                    uuid.New(),
							ScanID:                    uuid.New(),
							Name:                      "Apache HTTP Server",
							Version:                   "2.4.46",
							Family:                    "Web Server",
							OsType:                    "Linux",
							Port:                      80,
							Protocol:                  "tcp",
							Fingerprint:               "Apache",
							Cpe:                       "cpe:/a:apache:http_server:2.4.46",
							Product:                   "Apache",
							Accuracy:                  90,
							PortState:                 "open",
							TotalVulnerabilitiesCount: 3,
							CriticalCount:             0,
							HighCount:                 1,
							MediumCount:               1,
							LowCount:                  1,
							NoneCount:                 0,
							UnknownCount:              0,
							CreatedAt:                 time.Now().AddDate(0, -2, 0),
							UpdatedAt:                 time.Now(),
						},
					}, nil
				},
			},
			vulnerability:       &mock_services.MockVulnerabilityService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/assets", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h := hh.NewScanHandlers(
				tt.scanService,
				tt.vulnerability,
				tt.scanScheduleService,
				tt.hostService,
				tt.emailService,
				tt.eventBus,
			)
			err := h.GetScanAssetsByID(rr, tt.r)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantStatus, rr.Code, "Expected http response code %d, got %d", tt.wantStatus, rr.Code)

			// Additional validation for the "Scan Status Ok → 200" test case
			if tt.name == "Scan Status Ok → 200" && rr.Code == http.StatusOK {
				// Parse the response to validate vulnerability counts
				var response dto.ScanAssetsResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				assert.NoError(t, err, "Response should be valid JSON")

				// Validate OS asset counts are internally consistent
				os := response.OperatingSystem
				if os.ID != 0 { // OS is present
					osSeveritySum := os.CriticalCount + os.HighCount + os.MediumCount + os.LowCount + os.NoneCount + os.UnknownCount
					assert.Equal(t, os.TotalVulnerabilities, osSeveritySum, "OS total vulnerabilities should equal sum of severity counts")
				}

				// Validate each service asset counts are internally consistent
				for i, svc := range response.Services {
					svcSeveritySum := svc.CriticalCount + svc.HighCount + svc.MediumCount + svc.LowCount + svc.NoneCount + svc.UnknownCount
					assert.Equal(t, svc.TotalVulnerabilities, svcSeveritySum, "Service %d total vulnerabilities should equal sum of severity counts", i)
				}

				// Validate that asset counts sum correctly across the scan
				totalCritical := os.CriticalCount
				totalHigh := os.HighCount
				totalMedium := os.MediumCount
				totalLow := os.LowCount
				totalNone := os.NoneCount
				totalUnknown := os.UnknownCount
				totalOverall := os.TotalVulnerabilities

				for _, svc := range response.Services {
					totalCritical += svc.CriticalCount
					totalHigh += svc.HighCount
					totalMedium += svc.MediumCount
					totalLow += svc.LowCount
					totalNone += svc.NoneCount
					totalUnknown += svc.UnknownCount
					totalOverall += svc.TotalVulnerabilities
				}

				// Verify that the sum of all severity counts equals the total vulnerability count
				allSeveritySum := totalCritical + totalHigh + totalMedium + totalLow + totalNone + totalUnknown
				assert.Equal(t, totalOverall, allSeveritySum, "Sum of all severity counts should equal total vulnerabilities across all assets")

				// Expected totals based on our test data:
				// OS: 5 total (1 critical, 2 high, 1 medium, 1 low)
				// Service: 3 total (0 critical, 1 high, 1 medium, 1 low)
				// Total: 8 vulnerabilities
				assert.Equal(t, 8, totalOverall, "Total vulnerabilities across all assets should match expected sum")
				assert.Equal(t, 1, totalCritical, "Total critical vulnerabilities should match expected sum") // 1 from OS + 0 from Service
				assert.Equal(t, 3, totalHigh, "Total high vulnerabilities should match expected sum")         // 2 from OS + 1 from Service
				assert.Equal(t, 2, totalMedium, "Total medium vulnerabilities should match expected sum")     // 1 from OS + 1 from Service
				assert.Equal(t, 2, totalLow, "Total low vulnerabilities should match expected sum")           // 1 from OS + 1 from Service
			}
		})
	}
}

func TestScanHandlers_GetScanOperatingSystemVulnerabilitiesByID(t *testing.T) {
	scanID := uuid.New()

	vulnerabilities := []domain.ScanVulnerabilityDetail{
		{
			ID:       uuid.New(),
			ScanDate: time.Now(),
			Host: domain.HostItem{
				Alias:     "web-server-01",
				IPAddress: "192.168.1.100",
			},
			Port: &domain.PortItem{
				ID:       443,
				Protocol: "tcp",
			},
			OS: &domain.OSItem{
				Name: "Ubuntu",
				Type: "Linux",
			},
			Name:           "CVE-2023-1234",
			Severity:       "High",
			MaxCVSS:        9.8,
			RiskScore:      8.7,
			ImpactScore:    7.5,
			Likelihood:     "High",
			Access:         "Network",
			Complexity:     "Low",
			Privileges:     "None",
			Exploitability: "Functional",
			Description:    "Buffer overflow in XYZ service.",
			Comment:        "Needs immediate patching",
			VendorComments: []tools.VendorComment{
				{
					Organization: "Ubuntu",
					Comment:      "Patch available in latest update.",
					LastModified: time.Now(),
				},
			},
			References: []string{
				"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234",
			},
			Metrics: []tools.CVSSMetric{
				{
					Version:             "3.1",
					BaseScore:           9.8,
					ImpactScore:         0,
					Severity:            "",
					Access:              "",
					Complexity:          "",
					PrivilegesRequired:  "",
					IntegrityImpact:     "",
					AvailabilityImpact:  "",
					ExploitabilityScore: 5,
					Exploitability:      "",
				},
			},
			CWERemediation: []tools.CWERemediation{
				{
					ID:                 "CWE-120",
					Description:        "Classic Buffer Overflow",
					MitigationID:       "",
					Title:              "Error CWE",
					Phase:              []string{"architecture"},
					Effectiveness:      "Effective",
					EffectivenessNotes: "Effective Notes",
					LastUpdated:        time.Time{},
				},
			},
			EPSSScore:      new(float64),
			EPSSPercentile: new(float64),
			EPSSDate:       new(time.Time),
			DateInfo: domain.DateInfo{
				Published:   time.Now().AddDate(-1, 0, 0),
				LastUpdated: time.Now().AddDate(0, -1, 0),
			},
			PluginInfo: domain.PluginInfo{
				CPE:      "cpe:/o:ubuntu:ubuntu_linux:20.04",
				Severity: "High",
				Version:  "20.04",
				Type:     "OS",
				Family:   "Linux",
			},
			VPRKeyD: domain.VPRKeyInfo{
				ThreatIntensity: "High",
				ExploitMaturity: "Mature",
				VulnAge:         365,
				ProductCoverage: "Wide",
			},
			RiskInfo: domain.RiskInfo{
				RiskScore:          8.7,
				AvailabilityImpact: "High",
				IntegrityImpact:    "High",
				CVSSV3Base:         9.8,
				CVSSV30Vector:      "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		},
	}

	tests := []struct {
		name                string
		scanService         interfaces.IScanService
		scanScheduleService interfaces.IScanScheduleService
		vulnerability       interfaces.IVulnerabilityService
		hostService         interfaces.IHostService
		emailService        interfaces.IEmailService
		eventBus            events.EventBus
		r                   *http.Request
		wantStatus          int
	}{
		{
			name:                "Scan Bad Request → 400",
			scanService:         &mock_services.MockScanService{},
			vulnerability:       &mock_services.MockVulnerabilityService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans//operating-system/vulnerabilities", nil)
				r.SetPathValue("id", "")
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Scan Not Completed → 409",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Failed"}, nil // not Completed
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/operating-system/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusConflict,
		},
		{
			name: "Scan - Vulnerabilities Not Found → 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
			},
			vulnerability: &mock_services.MockVulnerabilityService{
				MockGetOSVulnerabilityDetailByScanID: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/assets", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusOK,
		},
		{
			name: "Scan - Status OK -> 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetSeverityCountsFromDomainVulnDetail: func(ctx context.Context, vulns []domain.ScanVulnerabilityDetail) tools.SeverityCounts {
					return tools.SeverityCounts{
						Critical: 0,
						High:     0,
						Medium:   0,
						Low:      0,
						None:     0,
						Unknown:  0,
					}
				},
			},
			vulnerability: &mock_services.MockVulnerabilityService{
				MockGetOSVulnerabilityDetailByScanID: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanVulnerabilityDetail, error) {
					return vulnerabilities, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/assets", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h := hh.NewScanHandlers(
				tt.scanService,
				tt.vulnerability,
				tt.scanScheduleService,
				tt.hostService,
				tt.emailService,
				tt.eventBus,
			)
			err := h.GetScanOperatingSystemVulnerabilitiesByID(rr, tt.r)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantStatus, rr.Code, "Expected http response code %d, got %d", tt.wantStatus, rr.Code)
		})
	}
}

func TestScanHandlers_GetScanServicesVulnerabilitiesByServiceID(t *testing.T) {
	scanID := uuid.New()
	vulnID := uuid.New()
	serviceID := 42
	titleWebVuln := "Cross Site Scripting (Reflected)"
	titleVuln := "CVE-2024-5985"
	mitigationID := "MIT-1"
	cweID := "CWE-168"
	scanDate := time.Now()
	tests := []struct {
		name                string
		scanService         interfaces.IScanService
		vulnService         interfaces.IVulnerabilityService
		scanScheduleService interfaces.IScanScheduleService
		hostService         interfaces.IHostService
		emailService        interfaces.IEmailService
		eventBus            events.EventBus
		r                   *http.Request
		wantStatus          int
		wantBodyContains    []string
	}{
		{
			name:                "Bad ScanID → 400",
			scanService:         &mock_services.MockScanService{},
			vulnService:         &mock_services.MockVulnerabilityService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/invalid/services/42/vulnerabilities", nil)
				r.SetPathValue("id", "invalid")
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: []string{},
		},
		{
			name: "Scan Not Found → 404",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return nil, customerrors.ErrScanNotFound
				},
			},
			vulnService:         &mock_services.MockVulnerabilityService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusNotFound,
			wantBodyContains: []string{},
		},
		{
			name: "Scan Not Completed → 409",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "InProgress"}, nil
				},
			},
			vulnService:         &mock_services.MockVulnerabilityService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusConflict,
			wantBodyContains: []string{},
		},
		{
			name: "Bad ServiceID → 400",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
			},
			vulnService:         &mock_services.MockVulnerabilityService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/invalid/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", "invalid")
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: []string{},
		},
		{
			name: "Service not found for scan → 404",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetSeverityServiceCountsByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
					return tools.SeverityCounts{}, customerrors.ErrServiceNotFound
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return []domain.WebVulnerability{}, nil
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{
						ID: serviceID,
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusNotFound,
			wantBodyContains: []string{"Service not found for scan"},
		},
		{
			name: "Error Getting Service Vulnerability Details → 500",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return nil, errors.New("error getting vuln for service")
				},

				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: []string{},
		},
		{
			name: "Error in Get Web Vulnerabilities → 500",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return nil, errors.New("error getting web vuln for service")
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: []string{},
		},
		{
			name: "No vulnerabilities returns empty response → 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetSeverityServiceCountsByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
					return tools.SeverityCounts{}, nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return []domain.WebVulnerability{}, nil
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusOK,
			wantBodyContains: []string{},
		},
		{
			name: "Service with only web vulnerabilities returns partial data → 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{
						ID:        scanID,
						CreatedAt: scanDate,
						Status:    "Completed"}, nil
				},
				MockGetSeverityServiceCountsByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
					return tools.SeverityCounts{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      4,
					}, nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return []domain.WebVulnerability{
						{
							VulnerabilityID: vulnID,
						},
					}, nil
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{
						SvName: "http",
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusOK,
			// Ensure that we return service and scan metadata
			wantBodyContains: []string{"http", scanID.String(), scanDate.Format("2006-01-02T15:04:05")},
		},
		{
			name: "Error in serviceID detail → 500",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{
						{
							ID: vulnID,
						},
					}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return []domain.WebVulnerability{
						{
							VulnerabilityID: vulnID,
						},
					}, nil
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return nil, errors.New("error in fetch service")
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: []string{},
		},

		{
			name: "Error in SeverityCounts → 500",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetSeverityServiceCountsByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
					return tools.SeverityCounts{}, errors.New("error in severityCounts")
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{
						{
							ID: vulnID,
						},
					}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return []domain.WebVulnerability{
						{
							VulnerabilityID: vulnID,
						},
					}, nil
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/"+strconv.Itoa(serviceID)+"/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", strconv.Itoa(serviceID))
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: []string{},
		},
		{
			name: "Status OK → 200",
			scanService: &mock_services.MockScanService{
				MockGetScanByID: func(ctx context.Context, id uuid.UUID) (*domain.Scan, error) {
					return &domain.Scan{Status: "Completed"}, nil
				},
				MockGetSeverityServiceCountsByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
					return tools.SeverityCounts{
						Critical: 1,
						High:     2,
						Medium:   3,
						Low:      4,
					}, nil
				},
			},
			vulnService: &mock_services.MockVulnerabilityService{
				MockGetServiceVulnerabilityDetailByScanAndServiceID: func(ctx context.Context, scanID uuid.UUID, serviceID int32) ([]domain.ScanVulnerabilityDetail, error) {
					return []domain.ScanVulnerabilityDetail{
						{
							ID:   vulnID,
							Name: titleVuln,
							CWERemediation: []tools.CWERemediation{
								{
									MitigationID: mitigationID,
									Description:  "Example mitigation description",
								},
							},
						},
					}, nil
				},
				MockGetWebVulnerabilitiesForService: func(ctx context.Context, serviceID int32) ([]domain.WebVulnerability, error) {
					return []domain.WebVulnerability{
						{
							VulnerabilityID: vulnID,
							ServiceID:       serviceID,
							Title:           "Cross Site Scripting (Reflected)",
							Severity:        enums.SeverityTypeHigh.String(),
							Instances: []domain.WebVulnerabilityInstance{
								{
									URI: "url1",
								},
								{
									URI: "url2",
								},
							},
							CWERemediations: []domain.CWEDetailWithMitigations{
								{
									CweID:        cweID,
									MitigationID: mitigationID,
								},
							},
						},
					}, nil
				},
				MockGetServiceByID: func(ctx context.Context, serviceID int32) (*domain.Service, error) {
					return &domain.Service{
						SvName: "http",
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/services/42/vulnerabilities", nil)
				r.SetPathValue("id", scanID.String())
				r.SetPathValue("service_id", "42")
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusOK,
			wantBodyContains: []string{"http", "HIGH"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h := hh.NewScanHandlers(
				tt.scanService,
				tt.vulnService,
				tt.scanScheduleService,
				tt.hostService,
				tt.emailService,
				tt.eventBus,
			)
			err := h.GetScanServicesVulnerabilitiesByServiceID(rr, tt.r)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantStatus, rr.Code, "Expected http response code %d, got %d", tt.wantStatus, rr.Code)
			body := rr.Body.String()
			for _, substr := range tt.wantBodyContains {
				assert.Contains(t, body, substr, "Response body should contain %q", substr)
			}
			// Additional validation for "Status OK → 200"
			if tt.name == "Status OK → 200" && rr.Code == http.StatusOK {
				var resp dto.ScanVulnerabilityDetectedServiceResponse
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Equal(t, "http", resp.ServiceName)
				assert.Equal(t, 1, resp.SeverityCounts.Critical)
				assert.Equal(t, 2, resp.SeverityCounts.High)
				assert.Equal(t, 3, resp.SeverityCounts.Medium)
				assert.Equal(t, 4, resp.SeverityCounts.Low)
				assert.Equal(t, titleVuln, resp.Vulnerabilities[0].Name)
				assert.Equal(t, mitigationID, *resp.Vulnerabilities[0].CWERemediations[0].MitigationID)
				assert.Equal(t, 2, resp.WebVulnerabilities[0].InstancesCount)
				assert.Equal(t, strconv.Itoa(serviceID), resp.WebVulnerabilities[0].ServiceID)
				assert.Equal(t, titleWebVuln, resp.WebVulnerabilities[0].Title)
				assert.Equal(t, enums.SeverityTypeHigh.String(), resp.WebVulnerabilities[0].Severity)
				assert.Equal(t, mitigationID, resp.WebVulnerabilities[0].CWERemediations[0].MitigationID)
				assert.Equal(t, cweID, resp.WebVulnerabilities[0].CWERemediations[0].CweID)
			}
		})
	}
}

func TestScanHandlers_GetScanResultsByScanID(t *testing.T) {
	scanID := uuid.New()
	tests := []struct {
		name                string
		scanService         interfaces.IScanService
		scanScheduleService interfaces.IScanScheduleService
		vulnerability       interfaces.IVulnerabilityService
		hostService         interfaces.IHostService
		emailService        interfaces.IEmailService
		eventBus            events.EventBus
		r                   *http.Request
		wantStatus          int
		wantBodyContains    []string
		wantBodyNotContains []string
	}{
		{
			name:                "Scan Bad Request → 400",
			scanService:         &mock_services.MockScanService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans//information-gathered", nil)
				r.SetPathValue("id", "")
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "Scan In Progress with no scan results yet → 200",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return []domain.ScanResult{}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/assets", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusOK,
		},
		{
			name: "Scan Not Found → 404",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return nil, customerrors.ErrScanNotFound
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/information-gathered", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus: http.StatusNotFound,
		},
		{
			name: "Empty Scan Result in every info-gathered tool → 200",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return []domain.ScanResult{
						{
							ScanID:   scanID,
							ToolName: enums.ToolDNSLookup.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolDNSLookup,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolWhoIs.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolWhoIs,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolHarvester.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolHarvester,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/information-gathered", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:       http.StatusOK,
			wantBodyContains: []string{"{}"},
		},
		{
			name: "DNSLookup Result only → 200",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return []domain.ScanResult{
						{
							ScanID:   scanID,
							ToolName: enums.ToolDNSLookup.String(),
							Success:  true,
							Result: tools.ToolResult{
								Tool: enums.ToolDNSLookup,
								Result: &tools.DNSLookupResult{
									Domain: "domain1",
									DNSRecords: []tools.DNSRecord{{
										Type:     "A",
										Name:     "",
										TTL:      0,
										Value:    "93.184.216.34",
										Priority: nil,
									},
									},
									DNSSECEnabled:  true,
									LookupDuration: 10,
								},
								Err: nil,
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolWhoIs.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolWhoIs,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolHarvester.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolHarvester,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/information-gathered", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:          http.StatusOK,
			wantBodyContains:    []string{"dns_lookup_result"},
			wantBodyNotContains: []string{"harvester_result", "whois_result"},
		},
		{
			name: "WhoIs Result only with partial data → 200",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return []domain.ScanResult{
						{
							ScanID:   scanID,
							ToolName: enums.ToolWhoIs.String(),
							Success:  true,
							Result: tools.ToolResult{
								Tool: enums.ToolWhoIs,
								Result: &tools.WhoIsResult{
									RawData: &whoisparser.WhoisInfo{
										Domain: nil,
										Registrar: &whoisparser.Contact{
											Name:  "jose",
											Email: "jose@co.co",
										},
										Registrant:     nil,
										Administrative: nil,
										Technical:      nil,
										Billing:        nil,
									},
								},
								Err: nil,
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolDNSLookup.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolDNSLookup,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolHarvester.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolHarvester,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/information-gathered", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:          http.StatusOK,
			wantBodyContains:    []string{"whois_result", "jose", "jose@co.co"},
			wantBodyNotContains: []string{"harvester_result", "dns_lookup_result"},
		},
		{
			name: "WhoIs Result only with all data → 200",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return []domain.ScanResult{
						{
							ScanID:   scanID,
							ToolName: enums.ToolWhoIs.String(),
							Success:  true,
							Result: tools.ToolResult{
								Tool: enums.ToolWhoIs,
								Result: &tools.WhoIsResult{
									RawData: &whoisparser.WhoisInfo{
										Domain: &whoisparser.Domain{
											Domain:      "domain",
											NameServers: []string{"name1"},
										},
										Registrar: &whoisparser.Contact{
											Name:  "jose",
											Email: "jose@co.co",
										},
										Registrant: &whoisparser.Contact{
											Name:         "martin",
											Organization: "peru",
										},
										Administrative: nil,
										Technical:      nil,
										Billing:        nil,
									},
								},
								Err: nil,
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolDNSLookup.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolDNSLookup,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolHarvester.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolHarvester,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/information-gathered", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:          http.StatusOK,
			wantBodyContains:    []string{"whois_result", "jose", "jose@co.co", "name1", "domain", "martin", "peru"},
			wantBodyNotContains: []string{"harvester_result", "dns_lookup_result"},
		},
		{
			name: "Harvester Result only → 200",
			scanService: &mock_services.MockScanService{
				MockGetInformationGatheredResults: func(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
					return []domain.ScanResult{
						{
							ScanID:   scanID,
							ToolName: enums.ToolHarvester.String(),
							Success:  true,
							Result: tools.ToolResult{
								Tool: enums.ToolHarvester,
								Result: &tools.HarvesterResult{
									Emails:     []string{"jose@co.co"},
									Subdomains: []string{"subdomain1"},
								},
								Err: nil,
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolWhoIs.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolWhoIs,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
						{
							ScanID:   scanID,
							ToolName: enums.ToolDNSLookup.String(),
							Success:  false,
							Result: tools.ToolResult{
								Tool:   enums.ToolDNSLookup,
								Result: nil,
								Err: &tools.ToolError{
									Code:    "400",
									Message: "No connection",
								},
							},
						},
					}, nil
				},
			},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r: func() *http.Request {
				r := httptest.NewRequest("GET", "/api/scans/"+scanID.String()+"/information-gathered", nil)
				r.SetPathValue("id", scanID.String())
				r = r.WithContext(context.WithValue(r.Context(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin}))
				return r
			}(),
			wantStatus:          http.StatusOK,
			wantBodyContains:    []string{"harvester_result", "jose@co.co", "subdomain1"},
			wantBodyNotContains: []string{"dns_lookup_result", "whois_result"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h := hh.NewScanHandlers(
				tt.scanService,
				tt.vulnerability,
				tt.scanScheduleService,
				tt.hostService,
				tt.emailService,
				tt.eventBus,
			)
			err := h.GetScanResultsByScanID(rr, tt.r)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantStatus, rr.Code, "Expected http response code %d, got %d", tt.wantStatus, rr.Code)
			body := rr.Body.String()
			for _, substr := range tt.wantBodyContains {
				assert.Contains(t, body, substr, "Response body should contain %q", substr)
			}
			for _, substr := range tt.wantBodyNotContains {
				assert.NotContains(t, body, substr, "Response body should not contain %q", substr)
			}
			if len(tt.wantBodyContains) > 0 && rr.Code == http.StatusOK {
				var resp dto.ScanInformationGatheredDTO
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				assert.NoError(t, err)
				switch tt.wantBodyContains[0] {
				case "harvester_result":
					assert.Greater(t, len(resp.HarvesterResult.Emails), 0)
					assert.Greater(t, len(resp.HarvesterResult.Subdomains), 0)
				case "dns_lookup_result":
					assert.Greater(t, len(resp.DNSLookupResult.DNSRecords), 0)
					assert.Greater(t, len(resp.DNSLookupResult.Domain), 0)
					assert.Equal(t, true, resp.DNSLookupResult.DNSSECEnabled)
				case "whois_result":
					if strings.Contains(tt.name, "partial") {
						assert.Equal(t, len(resp.WhoisResult.Domain.Name), 0)
						assert.Equal(t, len(resp.WhoisResult.Registrant.Name), 0)
						assert.Equal(t, len(resp.WhoisResult.Registrant.Organization), 0)
						assert.Greater(t, len(resp.WhoisResult.Registrar.Name), 0)
						assert.Greater(t, len(resp.WhoisResult.Registrar.Email), 0)
					} else {
						assert.Greater(t, len(resp.WhoisResult.Domain.Name), 0)
						assert.Greater(t, len(resp.WhoisResult.Registrant.Name), 0)
						assert.Greater(t, len(resp.WhoisResult.Registrant.Organization), 0)
					}
				}

			}
		})
	}
}

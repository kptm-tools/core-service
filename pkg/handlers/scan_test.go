package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
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
							AssetType:                 "host",
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
				MockGetSeverityOSCountsByScanID: func(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
					return tools.SeverityCounts{
						Critical: 0,
						High:     0,
						Medium:   0,
						Low:      0,
						None:     0,
						Unknown:  0,
					}, nil
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

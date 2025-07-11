package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/events"
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
			name: "Scan Not Found → 404",
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
			wantStatus: http.StatusNotFound,
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

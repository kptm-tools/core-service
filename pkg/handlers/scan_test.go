package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"

	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
)

func TestScanHandlers_GetScanAssetsByID(t *testing.T) {
	scanID := uuid.New()

	tests := []struct {
		name string

		scanService         interfaces.IScanService
		scanScheduleService interfaces.IScanScheduleService
		hostService         interfaces.IHostService
		emailService        interfaces.IEmailService
		eventBus            events.EventBus

		r              *http.Request
		wantStatus     int
		wantErrorField string                   // para errores
		wantData       []dto.ScanAssetsResponse // para 200 OK
	}{
		{
			name:                "Scan no completado → 409",
			scanService:         &mock_services.MockScanService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r:                   httptest.NewRequest("GET", fmt.Sprintf("/api/scans/%s/assets", scanID), nil).WithContext(context.WithValue(context.Background(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin})),
			wantStatus:          http.StatusConflict,
			wantErrorField:      "Scan status not completed",
		},
		{
			name:                "Completado sin assets → 404",
			scanService:         &mock_services.MockScanService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r:                   httptest.NewRequest("GET", fmt.Sprintf("/api/scans/%s/assets", scanID), nil).WithContext(context.WithValue(context.Background(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin})),
			wantStatus:          http.StatusNotFound,
			wantErrorField:      fmt.Sprintf("Scan Assets for the ID %s not found", scanID.String()),
		},
		{
			name:                "Error interno al obtener assets → 500",
			scanService:         &mock_services.MockScanService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r:                   httptest.NewRequest("GET", fmt.Sprintf("/api/scans/%s/assets", scanID), nil).WithContext(context.WithValue(context.Background(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin})),
			wantStatus:          http.StatusInternalServerError,
			wantErrorField:      "Internal server error",
		},
		{
			name:                "Éxito con datos → 200",
			scanService:         &mock_services.MockScanService{},
			scanScheduleService: &mock_services.MockScanScheduleService{},
			hostService:         &mock_services.MockHostService{},
			emailService:        &mock_services.MockEmailService{},
			eventBus:            &events.NatsEventBus{},
			r:                   httptest.NewRequest("GET", fmt.Sprintf("/api/scans/%s/assets", scanID), nil).WithContext(context.WithValue(context.Background(), middleware.ContextRoles, []domain.Role{domain.RoleAdmin})),
			wantStatus:          http.StatusOK,
			wantData:            []dto.ScanAssetsResponse{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			rr := httptest.NewRecorder()
			h := NewScanHandlers(tt.scanService, tt.scanScheduleService, tt.hostService, tt.emailService, tt.eventBus)
			h.GetScanAssetsByID(rr, tt.r)

			assert.Equal(t, tt.wantStatus, rr.Code, "Expected http response code %d, got %d", tt.wantStatus, rr.Code)
		})
	}
}

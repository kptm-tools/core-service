package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type DashboardHandlers struct {
	dashboardService interfaces.IDashboardService
}

var _ interfaces.IDashboardHandlers = (*DashboardHandlers)(nil)

func NewDashboardHandlers(dashboardService interfaces.IDashboardService) *DashboardHandlers {
	return &DashboardHandlers{
		dashboardService: dashboardService,
	}
}

func (h *DashboardHandlers) GetDashboard(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	tenantID, ok := ctx.Value(middleware.ContextTenantID).(uuid.UUID)
	if !ok {
		slog.Error("Failed to assert tenantID to UUID")
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	hostIDFilter, err := parseHostsIDFilterFromURLQuery(req, "host_ids")
	if err != nil {
		slog.Warn("Error parsing hostsIDFilter", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid host_ids filter. Must be comma-separated int e.g: '1,2,3,4'"})
	}

	trendsTimePeriodFilter, err := parseTimePeriodFilterFromURLQuery(req, "trends_time_period")
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid time_period filter Must be 'Month', 'Quarter', or 'Semester'"})
	}

	trendsSeverityFilter, err := parseSeverityFilterFromURLQuery(req, "trends_severity")
	if err != nil {
		slog.Warn("Error parsing severity filter", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid severity filter. Allowed values: Critical,High,Medium,Low"})
	}

	tenantDasboardData, err := h.dashboardService.GetTenantDashboardData(ctx, tenantID, trendsTimePeriodFilter, trendsSeverityFilter, hostIDFilter)
	if err != nil {
		slog.Error("Error getting tenant dashboard data",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	return api.WriteJSON(w, http.StatusOK, tenantDasboardData)
}

func parseTimePeriodFilterFromURLQuery(req *http.Request, queryKey string) (domain.TimePeriodFilter, error) {
	var err error
	timePeriodFilter := domain.TimePeriodFilterMonth

	timePeriodFilterStr := req.URL.Query().Get(queryKey)
	if timePeriodFilterStr != "" {
		timePeriodFilter, err = domain.ParseTimePeriodFilter(timePeriodFilterStr)
		if err != nil {
			slog.Warn("Invalid time_period filter query param",
				slog.String("time_period_filter", timePeriodFilterStr))
			return domain.TimePeriodFilterMonth, err
		}
	}
	return timePeriodFilter, nil
}

func parseSeverityFilterFromURLQuery(req *http.Request, queryKey string) ([]string, error) {
	severityFilterStr := req.URL.Query().Get(queryKey)
	var severityFilters []string
	if severityFilterStr != "" {
		severityFilters = strings.Split(severityFilterStr, ",")
		validSeverities := map[string]bool{
			"low":      true,
			"medium":   true,
			"high":     true,
			"critical": true,
		}
		for i, severity := range severityFilters {
			if !validSeverities[strings.ToLower(severity)] {
				return nil, fmt.Errorf("invalid severity filter: %s", severity)
			}
			severityFilters[i] = strings.ToLower(severity)
		}
	}

	return severityFilters, nil
}

func parseHostsIDFilterFromURLQuery(req *http.Request, queryKey string) ([]uuid.UUID, error) {
	hostIDFilter := req.URL.Query().Get(queryKey)

	var hostIDs []uuid.UUID
	if hostIDFilter != "" {
		for _, hostIDStr := range strings.Split(hostIDFilter, ",") {
			hostID, err := uuid.Parse(hostIDStr)
			if err != nil {
				return nil, fmt.Errorf("invalid host ID: %s", hostIDStr)
			}
			hostIDs = append(hostIDs, hostID)
		}
	}

	return hostIDs, nil
}

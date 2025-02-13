package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type ScanHandlers struct {
	scanService interfaces.IScanService
	eventBus    cmmn.EventBus
}

var _ interfaces.IScanHandlers = (*ScanHandlers)(nil)

func NewScanHandlers(scanService interfaces.IScanService, bus cmmn.EventBus) *ScanHandlers {
	return &ScanHandlers{
		scanService: scanService,
		eventBus:    bus,
	}
}

func (h *ScanHandlers) CreateScans(w http.ResponseWriter, req *http.Request) error {
	tenantID := req.Context().Value(middleware.ContextTenantID).(string)
	userID := req.Context().Value(middleware.ContextUserID).(string)
	scanRequest := new(ScanRequest)

	if err := decodeJSONBody(w, req, scanRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	var hostIDs []int
	for _, strID := range scanRequest.HostIds {
		intID, err := strconv.Atoi(strID)
		if err != nil {
			msg := fmt.Sprintf("invalid id: %s", strID)
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: msg})
		}
		hostIDs = append(hostIDs, intID)
	}

	scans, err := h.scanService.CreateScans(hostIDs, tenantID, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			statusCode := http.StatusNotFound
			return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
		}

		slog.Error("Failed to create scans", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	for _, createdScan := range scans {
		scanStartedPayload := &cmmn.ScanStartedEvent{
			BaseEvent: cmmn.BaseEvent{
				ScanID:    createdScan.ID,
				Timestamp: createdScan.CreatedAt.UTC(),
			},
			Target: createdScan.Target,
		}
		scanStartedBytes, err := json.Marshal(scanStartedPayload)
		if err != nil {
			return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
		}
		h.eventBus.Publish(string(enums.ScanStartedEventSubject), scanStartedBytes)

	}

	return api.WriteJSON(w, http.StatusCreated, scans)
}

func (h ScanHandlers) GetScans(w http.ResponseWriter, r *http.Request) error {
	tenantID := r.Context().Value(middleware.ContextTenantID).(string)
	scans, err := h.scanService.GetScans(tenantID)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	return api.WriteJSON(w, http.StatusCreated, scans)
}

func (h *ScanHandlers) CancelScanByID(w http.ResponseWriter, req *http.Request) error {
	scanID, err := GetUUID(req)
	if err != nil {
		slog.Error("failed to extract scanID", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: http.StatusText(http.StatusBadRequest)})
	}

	// 1. Publish the event
	scanCancelledPayload := &cmmn.ScanCancelledEvent{
		BaseEvent: cmmn.BaseEvent{
			ScanID:    scanID,
			Timestamp: time.Now().UTC(),
		},
	}
	scanCancelledBytes, err := json.Marshal(scanCancelledPayload)
	if err != nil {
		slog.Error("failed to unmarshal scanCancelledEvent", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	if err := h.eventBus.Publish(string(enums.ScanCancelledEventSubject), scanCancelledBytes); err != nil {
		slog.Error("Failed to publish ScanCancelledEvent", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	// 2. Update scan status and ended_at in our storage
	if err := h.scanService.MarkScanAsCancelled(scanID); err != nil {
		slog.Error("Failed to mark scan as cancelled", slog.Any("error", err))
		var alreadyFinishedErr *customerrors.ScanAlreadyFinishedError
		if errors.As(err, &alreadyFinishedErr) {
			return api.WriteJSON(w, http.StatusConflict, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusOK, "Scan was cancelled")
}

func (h *ScanHandlers) GetScanInsightsByID(w http.ResponseWriter, r *http.Request) error {
	scanID, err := GetUUID(r)
	if err != nil {
		slog.Error("failed to extract scanID", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: http.StatusText(http.StatusBadRequest)})
	}

	summary, err := h.scanService.GetScanInsightsByID(scanID)
	if err != nil {
		slog.Error("failed to get scan summary by ID", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusOK, summary)
}

func (h *ScanHandlers) GetScanVulnerabilitySummaryByID(w http.ResponseWriter, r *http.Request) error {
	scanID, err := GetUUID(r)
	if err != nil {
		slog.Error("failed to extract scanID", slog.Any("err", err))
	}

	timePeriodFilter := r.URL.Query().Get("time_period")
	validTimePeriods := map[string]bool{"Month": true, "Quarter": true, "Semester": true}
	if !validTimePeriods[timePeriodFilter] {
		slog.Warn("Invalid time_period filter",
			slog.String("time_period_filter", timePeriodFilter))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid time_period filter Must be 'Month', 'Quarter', or 'Semester'"})
	}

	severityFilterStr := r.URL.Query().Get("severity")
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
				return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid severity filter. Allowed values: Critical,High,Medium,Low"})
			}
			severityFilters[i] = strings.ToLower(severity)
		}
	}

	summaryData, err := h.scanService.GetScanVulnerabilitySummaryByID(scanID, timePeriodFilter, severityFilters)
	if err != nil {
		slog.Error("failed to get scan vulnerabilities summary",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	if summaryData == nil {
		return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: "Scan summary not found"})
	}

	// Map from service layer struct to API response DTO
	response := ScanVulnerabilitySummaryResponse{
		ScanID: summaryData.ScanID.String(),
		Domain: summaryData.Domain,
		GeneralSummary: VulnerabilityGeneralSummary{
			TotalVulnerabilities: summaryData.TotalVulnerabilities,
			SeverityCounts:       summaryData.SeverityCounts,
			VulnerabilitiesByCategory: VulnerabilitiesByCategory{
				CategoryData: adaptCategoryData(summaryData.CategoryData),
			},
			VulnerabilityTrends: VulnerabilityTrends{
				TimePeriods:               adaptTimePeriods(summaryData.VulnerabilityTrends.TimePeriods),
				AverageVulnerabilityCount: summaryData.VulnerabilityTrends.AverageVulnerabilityCount,
			},
		},
	}

	return api.WriteJSON(w, http.StatusOK, response)
}

func (h *ScanHandlers) GetReports(w http.ResponseWriter, r *http.Request) error {
	tenantID := r.Context().Value(middleware.ContextTenantID).(string)

	reportItems, err := h.scanService.GetAllReportsForTenant(tenantID)
	if err != nil {
		slog.Error("Failed to get all reports for tenant",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	reportResponses := make([]ReportsResponse, len(reportItems))
	for i, item := range reportItems {
		reportResponses[i] = ReportsResponse{
			ScanID:          item.ScanID.String(),
			Domain:          item.HostName,
			IP:              item.IP,
			ScanDate:        item.ScanDate,
			TotalSeverities: item.TotalSeverities,
			CommentStatus:   item.CommentStatus.String(),
		}
	}

	return api.WriteJSON(w, http.StatusOK, reportResponses)
}

func (h *ScanHandlers) GetScoreCardTrends(w http.ResponseWriter, r *http.Request) error {
	tenantID := r.Context().Value(middleware.ContextTenantID).(string)

	scoreCardTrendItems, err := h.scanService.GetScoreCardTrendsForTenant(tenantID)
	if err != nil {
		slog.Error("Failed to get ScoreCard trends for tenant",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	scoreCardResponses := make([]ScoreCardTrendResponse, len(scoreCardTrendItems))
	for i, item := range scoreCardTrendItems {
		scoreCardResponses[i] = ScoreCardTrendResponse{
			Alias:            item.Alias,
			OldestScore:      item.OldestScore,
			LatestScore:      item.LatestScore,
			LatestScoreGrade: item.LatestScoreGrade,
		}
	}

	return api.WriteJSON(w, http.StatusOK, scoreCardResponses)
}

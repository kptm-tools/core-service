package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type ScanHandlers struct {
	scanService interfaces.IScanService
	hostService interfaces.IHostService
	scanScheduleService interfaces.IScanScheduleService
	eventBus            cmmn.EventBus
}

var _ interfaces.IScanHandlers = (*ScanHandlers)(nil)

func NewScanHandlers(
	scanService interfaces.IScanService,
	hostService interfaces.IHostService,
	bus cmmn.EventBus,
) *ScanHandlers {
	return &ScanHandlers{
		scanService: scanService,
		hostService: hostService,
		scanScheduleService: scanScheduleService,
		eventBus:            bus,
	}
}

func (h *ScanHandlers) CreateScan(w http.ResponseWriter, req *http.Request) error {
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
	var scan *domain.Scan
	var err error
	if scanRequest.ScheduleAt == nil {
		scan, err = h.scanService.CreateScan(scanRequest.HostID, tenantID, userID, nil)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				statusCode := http.StatusNotFound
				return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
			}

			slog.Error("Failed to create scans", slog.Any("error", err))
			return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
		}
		scanStartedPayload := &cmmn.ScanStartedEvent{
			BaseEvent: cmmn.BaseEvent{
				ScanID:    scan.ID,
				Timestamp: scan.CreatedAt.UTC(),
			},
			Target: scan.Target,
		}
		scanStartedBytes, err := json.Marshal(scanStartedPayload)
		if err != nil {
			return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
		}
		h.eventBus.Publish(string(enums.ScanStartedEventSubject), scanStartedBytes)

	} else {
		dateSchedule, errParsingDate := time.Parse("2006-01-02T15:04:05.000Z", *scanRequest.ScheduleAt)
		if errParsingDate != nil {
			slog.Error("Failed to parse schedule_at to DateTime format",
				slog.Any("error", errParsingDate))
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
				Error: "Invalid schedule_at field. Must follow DateOnly format e.g: '2025-02-26T20:57:51.000Z'",
			})
		}
		now := time.Now().UTC()
		if now.After(dateSchedule) || now.Equal(dateSchedule) {
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
				Error: "Invalid schedule_at field. Must be greater than now",
			})
		}
		scan, err = h.scanService.CreateScan(scanRequest.HostID, tenantID, userID, &dateSchedule)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				statusCode := http.StatusNotFound
				return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
			}

			slog.Error("Failed to create scans", slog.Any("error", err))
			return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
		}
		errScanSchedule := h.scanScheduleService.InsertScanScheduling(scan.ID, dateSchedule, scanRequest.Frequency)
		if errScanSchedule != nil {
			msg := fmt.Sprintf("invalid scheduling: %s", *scanRequest.ScheduleAt)
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: msg})
		}
	}

	return api.WriteJSON(w, http.StatusCreated, scan)
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
	if timePeriodFilter == "" {
		timePeriodFilter = "Month"
	}

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
		},
		VulnerabilitiesByCategory: VulnerabilitiesByCategory{
			CategoryData: adaptCategoryData(summaryData.CategoryData),
		},
		VulnerabilityTrends: VulnerabilityTrends{
			TimePeriods:               adaptTimePeriods(summaryData.VulnerabilityTrends.TimePeriods),
			AverageVulnerabilityCount: summaryData.VulnerabilityTrends.AverageVulnerabilityCount,
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

	fromDate, toDate, err := h.parseDateRange(w, r)
	if err != nil {
		return err
	}

	var scoreCardTrendItems []*domain.ScoreCardTrendItem
	scoreCardTrendItems, err = h.scanService.GetScoreCardTrendsForTenant(tenantID, fromDate, toDate)
	if err != nil {
		slog.Error("Failed to get ScoreCard trends for tenant",
			slog.String("tenant_id", tenantID),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	scoreCardResponses := make([]ScoreCardTrendResponse, len(scoreCardTrendItems))
	for i, item := range scoreCardTrendItems {
		if item == nil {
			continue
		}
		scoreCardResponses[i] = ScoreCardTrendResponse{
			Alias:            item.Alias,
			OldestScore:      item.OldestScore,
			LatestScore:      item.LatestScore,
			LatestScoreGrade: item.LatestScoreGrade,
		}
	}

	return api.WriteJSON(w, http.StatusOK, scoreCardResponses)
}

func (h *ScanHandlers) parseDateRange(w http.ResponseWriter, r *http.Request) (fromDate *time.Time, toDate *time.Time, err error) {
	fromDateStr := r.URL.Query().Get("from_date")
	toDateStr := r.URL.Query().Get("to_date")

	if fromDateStr != "" {
		parsedFromDate, parseErr := time.Parse(time.DateOnly, fromDateStr)
		if parseErr != nil {
			slog.Error("Failed to parse from_date to DateOnly format",
				slog.String("from_date_str", fromDateStr),
				slog.Any("error", err))
			err = api.WriteJSON(w, http.StatusBadRequest, api.APIError{
				Error: "Invalid from_date filter. Must follow DateOnly format e.g: '2006-01-02'",
			})
			return
		}
		fromDate = &parsedFromDate
	}

	if toDateStr != "" {
		parsedToDate, parseErr := time.Parse(time.DateOnly, toDateStr)
		if parseErr != nil {
			slog.Error("Failed to parse to_date to DateOnly format",
				slog.String("to_date_str", toDateStr),
				slog.Any("error", err))
			err = api.WriteJSON(w, http.StatusBadRequest, api.APIError{
				Error: "Invalid from_date filter. Must follow DateOnly format e.g: '2006-01-02'",
			})
			return
		}
		toDate = &parsedToDate
	}
	return
}

func (h *ScanHandlers) GetScanVulnerabilities(w http.ResponseWriter, r *http.Request) error {
	scanID, err := GetUUID(r)
	if err != nil {
		slog.Error("failed to extract scanID", slog.Any("error", err))
	}

	scan, err := h.scanService.GetScanByID(scanID)
	if err != nil {
		if errors.Is(err, customerrors.ErrScanNotFound) {
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("Scan %s not found", scanID.String())})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	slog.Debug(
		"Attempting to GetHostByID",
		slog.String("scan_id", scanID.String()),
		slog.Int("host_id", scan.HostID),
	)
	host, err := h.hostService.GetHostByID(scan.HostID)
	if err != nil {
		if errors.Is(err, customerrors.ErrHostNotFound) {
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("No host found for scan %s", scanID.String())})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	vulners, err := h.scanService.GetScanVulnerabilities(scanID)
	if err != nil {
		slog.Error("failed to fetch scan vulnerabilities",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	severityCounts, err := h.scanService.GetSeverityCounts(scanID)
	if err != nil {
		slog.Error("failed to fetch severity counts",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	var scanVulnersItemsResponse ScanVulnerabilityItemsResponse

	// Parse vulners
	scanVulnerItems := make([]ScanVulnerabilityItem, len(vulners))
	for i, vuln := range vulners {
		var analystComment string
		if vuln.AnalystComment == nil {
			analystComment = ""
		}

		scanVulnerItems[i] = ScanVulnerabilityItem{
			ID:             vuln.ID,
			Name:           vuln.VulnerabilityID,
			Severity:       vuln.BaseSeverity.String(),
			MaxCVSS:        vuln.BaseCVSSScore,
			RiskScore:      vuln.RiskScore,
			ImpactScore:    vuln.ImpactScore,
			Likelihood:     vuln.Likelihood.String(),
			Access:         vuln.AccessType.String(),
			Complexity:     vuln.Complexity.String(),
			Privileges:     vuln.PrivilegesRequired.String(),
			Exploitability: vuln.Exploit.Exploitability.String(),
			Description:    vuln.Description,
			Comment:        analystComment,
			References:     vuln.References,
		}
	}

	// Associate scan and host alias
	scanVulnersItemsResponse.ScanDate = scan.StartedAt
	scanVulnersItemsResponse.Alias = host.Name
	// Associate vulners
	scanVulnersItemsResponse.Vulnerabilities = scanVulnerItems
	scanVulnersItemsResponse.TotalVulnerabilities = len(scanVulnersItemsResponse.Vulnerabilities)
	// Associate SeverityCounts
	if severityCounts != nil {
		scanVulnersItemsResponse.SeverityCounts = *severityCounts
	}

	return api.WriteJSON(w, http.StatusOK, scanVulnersItemsResponse)
}

func (h *ScanHandlers) DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error {
	id, err := GetID(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	isDeleted, err := h.scanService.DeleteScanScheduleByID(id)
	if err != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	result := make(map[string]string)
	if isDeleted {
		result["deleted"] = "true"
	} else {
		result["deleted"] = "false"
	}
	return api.WriteJSON(w, http.StatusOK, result)
}

func (h *ScanHandlers) PatchScanSchedule(w http.ResponseWriter, r *http.Request) error {
	//TODO implement me
	panic("implement me")
}

func (h *ScanHandlers) GetScanSchedules(w http.ResponseWriter, r *http.Request) error {
	//TODO implement me
	panic("implement me")
}

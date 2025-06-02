package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type ScanHandlers struct {
	scanService         interfaces.IScanService
	hostService         interfaces.IHostService
	scanScheduleService interfaces.IScanScheduleService
	emailService        interfaces.IEmailService
	eventBus            cmmn.EventBus
}

var _ interfaces.IScanHandlers = (*ScanHandlers)(nil)

func NewScanHandlers(
	scanService interfaces.IScanService,
	scanScheduleService interfaces.IScanScheduleService,
	hostService interfaces.IHostService,
	emailService interfaces.IEmailService,
	bus cmmn.EventBus,
) *ScanHandlers {
	return &ScanHandlers{
		scanService:         scanService,
		hostService:         hostService,
		scanScheduleService: scanScheduleService,
		eventBus:            bus,
		emailService:        emailService,
	}
}

func (h *ScanHandlers) CreateScan(w http.ResponseWriter, req *http.Request) error {
	ctx := req.Context()
	tenantID, ok := ctx.Value(middleware.ContextTenantID).(uuid.UUID)
	if !ok {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: "invalid tenantID"})
	}
	userID, ok := ctx.Value(middleware.ContextUserID).(uuid.UUID)
	if !ok {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: "invalid tenantID"})
	}

	scanRequest := new(dto.ScanRequest)

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
		scan, err = h.scanService.CreateScan(ctx, scanRequest.HostID, tenantID, userID, nil)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				statusCode := http.StatusNotFound
				return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
			}
			if errors.Is(err, customerrors.ErrScanHostFKNotFound) {
				return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("No host %s found ", scanRequest.HostID)})
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
		twoMinuteLater := now.Add(2 * time.Minute)
		if !dateSchedule.After(twoMinuteLater) {
			slog.Warn("ScanSchedule rejected, must be at least 2 minutes greater than current time",
				slog.String("current_time", now.Format(time.DateTime)),
				slog.String("two_minutes_later", twoMinuteLater.Format(time.DateTime)))

			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
				Error: "Invalid schedule_at field. Must be at least 2 minutes greater than the current time",
			})
		}
		scan, err = h.scanService.CreateScan(ctx, scanRequest.HostID, tenantID, userID, &dateSchedule)
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
			slog.Error("Error inserting scan schedule",
				slog.String("scan_id", scan.ID.String()),
				slog.Time("schedule_at", dateSchedule),
				slog.Any("frequency", scanRequest.Frequency),
				slog.Any("error", errScanSchedule))

			msg := fmt.Sprintf("invalid scheduling: %s", *scanRequest.ScheduleAt)
			return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: msg})
		}
	}

	return api.WriteJSON(w, http.StatusCreated, scan)
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
	// 3. Get the emails rapporteurs structure
	rapporteurs, hostName, errorGerRapporteurs := h.scanService.GetRapporteursScan(scanID)
	if errorGerRapporteurs != nil {
		slog.Error("Can not obtain rapporteurs associated to the scan",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", errorGerRapporteurs))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: errorGerRapporteurs.Error()})
	}

	for _, rapporteur := range rapporteurs {
		if err := h.emailService.SendScanCompletedEmail(rapporteur.Email, hostName); err != nil {
			slog.Warn("Failed to send email to rapporteur",
				slog.String("scan_id", scanID.String()),
				slog.String("rapporteur_email", rapporteur.Email),
				slog.Any("error", err),
			)
			continue
		}
	}
	return api.WriteJSON(w, http.StatusOK, "Scan was cancelled")
}

func (h *ScanHandlers) GetScanInsightsByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scanID, err := GetUUID(r)
	if err != nil {
		slog.Error("failed to extract scanID", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: http.StatusText(http.StatusBadRequest)})
	}

	summary, err := h.scanService.GetScanInsights(ctx, scanID)
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

	timePeriodFilter, err := parseTimePeriodFilterFromURLQuery(r, "time_period")
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid time_period filter Must be 'Month', 'Quarter', or 'Semester'"})
	}

	severityFilters, err := parseSeverityFilterFromURLQuery(r, "severity")
	if err != nil {
		slog.Warn("Error parsing severity filter", slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid severity filter. Allowed values: Critical,High,Medium,Low"})
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
	response := dto.ScanVulnerabilitySummaryResponse{
		ScanID: summaryData.ScanID.String(),
		Domain: summaryData.Domain,
		GeneralSummary: dto.VulnerabilityGeneralSummary{
			TotalVulnerabilities: summaryData.TotalVulnerabilities,
			SeverityCounts:       summaryData.SeverityCounts,
		},
		VulnerabilitiesByCategory: dto.VulnerabilitiesByCategory{
			CategoryData: dto.AdaptCategoryData(summaryData.CategoryData),
		},
		VulnerabilityTrends: dto.VulnerabilityTrends{
			TimePeriods:               dto.AdaptTimePeriods(summaryData.VulnerabilityTrends.TimePeriods),
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

	reportResponses := make([]dto.ReportsResponse, len(reportItems))
	for i, item := range reportItems {
		reportResponses[i] = dto.ReportsResponse{
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
	ctx := r.Context()
	tenantIDStr := ctx.Value(middleware.ContextTenantID).(string)
	tenantID := uuid.MustParse(tenantIDStr)

	fromDate, toDate, err := h.parseDateRange(w, r)
	if err != nil {
		return err
	}

	var scoreCardTrendItems []*domain.ScoreCardTrendItem
	scoreCardTrendItems, err = h.scanService.GetScoreCardTrendsForTenant(ctx, tenantID, fromDate, toDate)
	if err != nil {
		slog.Error("Failed to get ScoreCard trends for tenant",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}

	scoreCardResponses := make([]dto.ScoreCardTrendResponse, len(scoreCardTrendItems))
	for i, item := range scoreCardTrendItems {
		if item == nil {
			continue
		}
		scoreCardResponses[i] = dto.ScoreCardTrendResponse{
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
	ctx := r.Context()
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
		slog.String("host_id", scan.HostID.String()),
	)
	host, err := h.hostService.GetHostByID(ctx, scan.HostID)
	if err != nil {
		if errors.Is(err, customerrors.ErrHostNotFound) {
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("No host found for scan %s", scanID.String())})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	vulners, err := h.scanService.GetScanVulnerabilities(ctx, scanID)
	if err != nil {
		slog.Error("failed to fetch scan vulnerabilities",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	severityCounts, err := h.scanService.GetSeverityCounts(ctx, scanID)
	if err != nil {
		slog.Error("failed to fetch severity counts",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	var scanVulnersItemsResponse dto.ScanVulnerabilityItemsResponse

	// Parse vulners
	scanVulnerItems := make([]dto.ScanVulnerabilityItem, len(vulners))
	for i, vuln := range vulners {
		scanVulnerItems[i] = dto.ToScanVulnerabilityItem(vuln)
	}

	// Associate scan and host alias
	scanVulnersItemsResponse.ScanDate = scan.StartedAt
	scanVulnersItemsResponse.Alias = host.Name
	// Associate vulners
	scanVulnersItemsResponse.Vulnerabilities = scanVulnerItems
	scanVulnersItemsResponse.TotalVulnerabilities = len(scanVulnersItemsResponse.Vulnerabilities)
	// Associate SeverityCounts
	scanVulnersItemsResponse.SeverityCounts = severityCounts

	return api.WriteJSON(w, http.StatusOK, scanVulnersItemsResponse)
}

func (h *ScanHandlers) DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error {
	id, err := GetID(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	isDeleted, err := h.scanScheduleService.DeleteScanScheduleByID(id)
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

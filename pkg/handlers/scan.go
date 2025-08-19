package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
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
	vulnService         interfaces.IVulnerabilityService
	emailService        interfaces.IEmailService
	eventBus            cmmn.EventBus
}

var _ interfaces.IScanHandlers = (*ScanHandlers)(nil)

func NewScanHandlers(
	scanService interfaces.IScanService,
	vulnService interfaces.IVulnerabilityService,
	scanScheduleService interfaces.IScanScheduleService,
	hostService interfaces.IHostService,
	emailService interfaces.IEmailService,
	bus cmmn.EventBus,
) *ScanHandlers {
	return &ScanHandlers{
		scanService:         scanService,
		hostService:         hostService,
		scanScheduleService: scanScheduleService,
		vulnService:         vulnService,
		eventBus:            bus,
		emailService:        emailService,
	}
}

// CreateScan creates a new scan for a given host, with optional scheduling.
// @Summary      CreateScan
// @Description  Create a new scan for a given host. Optionally schedule the scan for a future time.
// @Tags         Scans
// @Accept       json
// @Produce      json
// @Param        scan  body      dto.ScanRequest  true  "Scan request payload"
// @Success      201   {object}  domain.Scan
// @Failure      400   {object}  api.APIError         "Invalid request payload"
// @Failure      404   {object}  api.APIError         "Host not found"
// @Failure      500   {object}  api.APIError         "Internal server error"
// @Security     BearerAuth
// @Router       /api/scans [post]
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
			if errors.Is(err, customerrors.ErrHostNotFound) {
				return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("Host %s not found ", scanRequest.HostID)})
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
		_, errScanSchedule := h.scanScheduleService.CreateScanSchedule(ctx, scan.ID, dateSchedule, scanRequest.Frequency, scanRequest.HostID)
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

// GetScanAssetsByID returns assets from the OS and Services based on the ScanID of the KPTM Tools - Core Service.
// @Summary      GetScanAssetsByID
// @Description  Retrieve assets from the OS and Services based on the ScanID of KPTM Tools - Core Service
// @Tags         Scans
// @Produce      json
// @Param        id             path      string  true  "Scan ID"
// @Success      200            {object}  dto.ScanAssetsResponse
// @Failure      401            {object}  api.APIError         "Unauthorized"
// @Failure      404            {object}  api.APIError         "Scan not found"
// @Failure      409            {object}  api.APIError         "Scan status not completed"
// @Failure      500            {object}  api.APIError         "Internal server error"
// @Security     BearerAuth
// @Router       /api/scans/{id}/assets [get]
func (h *ScanHandlers) GetScanAssetsByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	scanID, err := GetUUID(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid scan ID"})
	}

	scan, err := h.scanService.GetScanByID(ctx, scanID)
	if err != nil {
		slog.Error("Failed to get scan by ID",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err))
		if errors.Is(err, customerrors.ErrScanNotFound) {
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("Scan %s not found", scanID.String())})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	if scan.Status != "Completed" {
		return api.WriteJSON(w, http.StatusConflict, api.APIError{Error: "Scan status not completed"})
	}

	rawResults, err := h.scanService.GetScanAssetsByID(ctx, scanID)
	if err != nil {
		slog.Error("Failed to get scan assets",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: "Internal server error"})
	}

	if len(rawResults) == 0 {
		slog.Warn("No assets found for scan",
			slog.String("scan_id", scanID.String()))
		return api.WriteJSON(w, http.StatusOK, dto.ScanAssetsResponse{})
	}

	response := dto.ConvertScanOSandServicesResultToResponse(rawResults)

	return api.WriteJSON(w, http.StatusOK, response)
}

func (h *ScanHandlers) CancelScanByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scanID, err := GetUUID(r)
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
	if err := h.scanService.MarkScanAsCancelled(ctx, scanID); err != nil {
		slog.Error("Failed to mark scan as cancelled", slog.Any("error", err))
		var alreadyFinishedErr *customerrors.ScanAlreadyFinishedError
		if errors.As(err, &alreadyFinishedErr) {
			return api.WriteJSON(w, http.StatusConflict, api.APIError{Error: err.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}
	// 3. Get the emails rapporteurs structure
	rapporteurs, hostName, errorGerRapporteurs := h.scanService.GetScanRapporteursAndHostAlias(ctx, scanID)
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
	ctx := r.Context()
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

	summaryData, err := h.scanService.GetScanVulnerabilitySummaryByID(ctx, scanID, timePeriodFilter, severityFilters)
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
	ctx := r.Context()
	tenantID, ok := ctx.Value(middleware.ContextTenantID).(uuid.UUID)
	if !ok {
		slog.Error("Failed type assertion for tenantID", slog.String("type", fmt.Sprintf("%T", tenantID)))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "TenantID is invalid"})
	}

	reportItems, err := h.scanService.GetAllReportsForTenant(ctx, tenantID)
	if err != nil {
		slog.Error("Failed to get all reports for tenant",
			slog.String("tenant_id", tenantID.String()),
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
	tenantID, ok := ctx.Value(middleware.ContextTenantID).(uuid.UUID)
	if !ok {
		slog.Error(
			"Failed to assert tenantID to uuid.UUID type",
			"expected_type", "uuid.UUID",
			"actual_type", fmt.Sprintf("%T", tenantID),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	fromDate, toDate, err := h.parseDateRange(w, r)
	if err != nil {
		return err
	}

	var scoreCardTrendItems []*domain.ScoreCardTrendItem
	scoreCardTrendItems, err = h.scanService.GetScoreCardTrendsForTenant(ctx, tenantID, fromDate, toDate)
	if err != nil {
		slog.Error(
			"Failed to get ScoreCard trends for tenant",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", err),
		)
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
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "ScanID must be a UUID",
		})
	}

	scan, err := h.scanService.GetScanByID(ctx, scanID)
	if err != nil {
		slog.Error("Failed to get scan by ID", slog.String("scan_id", scanID.String()), slog.Any("error", err))
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
		slog.Error("Failed to get host by ID", slog.String("host_id", scan.HostID.String()), slog.Any("error", err))
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
	severityCounts := h.scanService.GetSeverityCountsFromToolVulns(ctx, vulners)

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

// GetScanOperatingSystemVulnerabilitiesByID returns operating system vulnerabilities and related details based on the ScanID.
// @Summary      GetScanOperatingSystemVulnerabilitiesByID
// @Description  Retrieve operating system vulnerabilities along with severity counts and remediation details for a given scan ID.
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "ScanID"
// @Success      200  {object}  dto.ScanVulnerabilityDetectedOSResponse
// @Failure      400  {object}  api.APIError         "Invalid UUID format for ScanID"
// @Failure      404  {object}  api.APIError         "Scan not found"
// @Failure      500  {object}  api.APIError         "Internal server error"
// @Security     BearerAuth
// @Router       /api/scans/{id}/operating-system/vulnerabilities [get]
func (h *ScanHandlers) GetScanOperatingSystemVulnerabilitiesByID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scanID, err := GetUUID(r)
	if err != nil {
		slog.Error("Failed to parse ScanID from request",
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid UUID format for ScanID",
		})
	}

	scan, err := h.scanService.GetScanByID(ctx, scanID)
	if err != nil {
		if errors.Is(err, customerrors.ErrScanNotFound) {
			slog.Warn("Scan not found",
				slog.String("scan_id", scanID.String()),
				slog.Any("error", err),
			)
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{
				Error: "Scan not found",
			})
		}
		slog.Error("Error fetching scan by ID",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	if scan.Status != "Completed" {
		return api.WriteJSON(w, http.StatusConflict, api.APIError{Error: "Scan status not completed"})
	}

	vulnerabilities, err := h.vulnService.GetOSVulnerabilityDetailByScanID(ctx, scanID)
	if err != nil {
		slog.Error("Failed to fetch scan vulnerabilities",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	if len(vulnerabilities) == 0 {
		slog.Warn("No vulnerabilities found for scan",
			slog.String("scan_id", scanID.String()))
		return api.WriteJSON(w, http.StatusOK, dto.ScanVulnerabilityDetectedOSResponse{})
	}

	severityCounts := h.scanService.GetSeverityCountsFromDomainVulnDetail(ctx, vulnerabilities)
	totalReferences := make([]string, 0)

	// Prepare vulnerability items slice
	scanVulnerabilityItems := make([]dto.ScanVulnerabilityItem, len(vulnerabilities))

	// Parse vulners
	for i, vuln := range vulnerabilities {
		doRemediations := make([]dto.CWERemediation, 0)
		doRemediations = h.getDomRemediationsToDto(vuln, doRemediations)
		// Populate ScanVulnerabilityItem
		scanVulnerabilityItems[i] = dto.ScanVulnerabilityItem{
			ID:              vuln.ID,
			Name:            vuln.Name,
			Type:            vuln.OS.Type,
			Severity:        vuln.Severity,
			MaxCVSS:         vuln.MaxCVSS,
			RiskScore:       vuln.RiskScore,
			ImpactScore:     vuln.ImpactScore,
			Likelihood:      vuln.Likelihood,
			Access:          vuln.Likelihood, // Consider if this is intentional or a mistake
			Complexity:      vuln.Complexity,
			Privileges:      vuln.Privileges,
			Exploitability:  vuln.Exploitability,
			Description:     vuln.Description,
			Comment:         vuln.Comment,
			VendorComments:  vuln.VendorComments,
			References:      vuln.References,
			CWERemediations: doRemediations,
		}

		// Aggregate references
		totalReferences = append(totalReferences, vuln.References...)
	}

	// Aggregate response object
	resp := dto.ScanVulnerabilityDetectedOSResponse{
		ScanDate:             scan.StartedAt,
		ScanID:               scanID.String(),
		Alias:                "",
		IPAddress:            "",
		OSName:               "",
		OSType:               "",
		Vulnerabilities:      scanVulnerabilityItems,
		References:           totalReferences,
		TotalVulnerabilities: severityCounts.Critical + severityCounts.High + severityCounts.Medium + severityCounts.Low + severityCounts.None + severityCounts.Unknown,
		SeverityCounts:       severityCounts,
	}

	// Guard access to first vuln fields, only if any vuln exist
	if len(vulnerabilities) > 0 {
		resp.Alias = vulnerabilities[0].Host.Alias
		resp.IPAddress = vulnerabilities[0].Host.IPAddress
		resp.OSName = vulnerabilities[0].OS.Name
		resp.OSType = vulnerabilities[0].OS.Type
	}

	slog.Info("Successfully returned OS vulnerabilities for scan",
		slog.String("scan_id", scanID.String()),
		slog.Int("vulnerability_count", len(scanVulnerabilityItems)),
	)

	return api.WriteJSON(w, http.StatusOK, resp)
}

// GetScanServicesVulnerabilitiesByServiceID returns service vulnerabilities and related details based on the ScanID.
// @Summary      GetScanServicesVulnerabilitiesByServiceID
// @Description  Retrieve service vulnerabilities along with severity counts and remediation details for a given scan ID.
// @Tags         Scans
// @Produce      json
// @Param        id   				  path      string  true  "ScanID"
// @Param        service_id     path      string  true  "ServiceID"
// @Success      200  {object}  dto.ScanVulnerabilityDetectedServiceResponse
// @Failure      400  {object}  api.APIError         "Invalid UUID format for ScanID"
// @Failure      404  {object}  api.APIError         "Scan not found"
// @Failure      500  {object}  api.APIError         "Internal server error"
// @Security     BearerAuth
// @Router       /api/scans/{id}/services/{service_id}/vulnerabilities [get]
func (h *ScanHandlers) GetScanServicesVulnerabilitiesByServiceID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	scanID, err := GetUUID(r)
	if err != nil {
		slog.Error("Failed to parse ScanID from request",
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid UUID format for ScanID",
		})
	}

	scan, err := h.scanService.GetScanByID(ctx, scanID)
	if err != nil {
		if errors.Is(err, customerrors.ErrScanNotFound) {
			slog.Warn("Scan not found",
				slog.String("scan_id", scanID.String()),
				slog.Any("error", err),
			)
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{
				Error: "Scan not found",
			})
		}
		slog.Error("Error fetching scan by ID",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	if scan.Status != "Completed" {
		return api.WriteJSON(w, http.StatusConflict, api.APIError{Error: "Scan status not completed"})
	}

	serviceID, err := GetIntCustomPathValue(r, "service_id")
	if err != nil {
		slog.Error("Failed to parse serviceID from request",
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid UUID format for serviceID",
		})
	}

	vulnerabilities, err := h.vulnService.GetServiceVulnerabilityDetailByScanAndServiceID(ctx, scanID, serviceID)
	if err != nil {
		slog.Error("Failed to fetch scan vulnerabilities",
			slog.String("scan_id", scanID.String()),
			slog.String("service_id", fmt.Sprintf("%d", serviceID)),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	webVulns, errWebVulns := h.vulnService.GetWebVulnerabilitiesForService(ctx, serviceID)

	if errWebVulns != nil {
		slog.Error("Failed to fetch scan vulnerabilities", slog.Any("error", errWebVulns))
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	serviceDetail, err := h.vulnService.GetServiceByID(ctx, serviceID)
	if err != nil {
		slog.Error("Failed to fetch service detail",
			slog.String("service_id", fmt.Sprintf("%d", serviceID)),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	severityCounts, err := h.scanService.GetSeverityServiceCountsByScanAndServiceID(ctx, scanID, serviceID)
	if err != nil {
		if errors.Is(err, customerrors.ErrServiceNotFound) {
			slog.Error("Service not found for scan", slog.String("scan_id", scanID.String()), slog.String("service_id", strconv.Itoa(int(serviceID))))
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{
				Error: "Service not found for scan",
			})
		}
		slog.Error("Failed to fetch severity counts",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err),
		)
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: http.StatusText(http.StatusInternalServerError),
		})
	}

	totalReferences := make([]string, 0)

	scanVulnerabilityItems := make([]dto.ScanVulnerabilityItem, len(vulnerabilities))

	// Parse vulners
	for i, vuln := range vulnerabilities {
		// Populate ScanVulnerabilityItem
		doRemediations := make([]dto.CWERemediation, 0)
		doRemediations = h.getDomRemediationsToDto(vuln, doRemediations)

		scanVulnerabilityItems[i] = dto.ScanVulnerabilityItem{
			ID:              vuln.ID,
			Name:            vuln.Name,
			Severity:        vuln.Severity,
			MaxCVSS:         vuln.MaxCVSS,
			RiskScore:       vuln.RiskScore,
			ImpactScore:     vuln.ImpactScore,
			Likelihood:      vuln.Likelihood,
			Access:          vuln.Likelihood,
			Complexity:      vuln.Complexity,
			Privileges:      vuln.Privileges,
			Exploitability:  vuln.Exploitability,
			Description:     vuln.Description,
			Comment:         vuln.Comment,
			VendorComments:  vuln.VendorComments,
			References:      vuln.References,
			CWERemediations: doRemediations,
		}

		// Aggregate references
		totalReferences = append(totalReferences, vuln.References...)

	}

	// Aggregate response object
	response := dto.ScanVulnerabilityDetectedServiceResponse{
		ScanID:               scanID.String(),
		ScanDate:             scan.CreatedAt,
		ServiceName:          serviceDetail.SvName,
		ServiceVersion:       serviceDetail.SvVersion,
		ServiceConfidence:    serviceDetail.Confidence,
		ServiceCPE:           serviceDetail.CPE,
		ServiceProduct:       serviceDetail.Product,
		ServiceProtocol:      serviceDetail.Protocol,
		ServicePort:          int(serviceDetail.Port),
		ServicePortState:     serviceDetail.PortState,
		TotalVulnerabilities: severityCounts.Critical + severityCounts.High + severityCounts.Medium + severityCounts.Low + severityCounts.None + severityCounts.Unknown,
		SeverityCounts:       severityCounts,
		Vulnerabilities:      scanVulnerabilityItems,
		WebVulnerabilities:   dto.ConvertToWebVulnSummaryToResponse(webVulns),
		References:           totalReferences,
	}

	slog.Info("Successfully returned OS vulnerabilities for scan",
		slog.String("scan_id", scanID.String()),
		slog.String("service_id", fmt.Sprintf("%d", serviceID)),
		slog.Int("vulnerability_count", len(scanVulnerabilityItems)),
	)

	return api.WriteJSON(w, http.StatusOK, response)
}

func (h *ScanHandlers) getDomRemediationsToDto(vuln domain.ScanVulnerabilityDetail, doRemediations []dto.CWERemediation) []dto.CWERemediation {
	for _, remediation := range vuln.CWERemediation {
		if remediation.Description != "" {
			var phasePtr *string
			if len(remediation.Phase) > 0 {
				phasePtr = &remediation.Phase[0]
			}

			cweRemediation := dto.CWERemediation{
				ID:                 remediation.ID,
				MitigationID:       &remediation.MitigationID,
				Title:              remediation.Title,
				Phase:              phasePtr, // Now validated
				Description:        remediation.Description,
				Effectiveness:      &remediation.Effectiveness,
				EffectivenessNotes: &remediation.EffectivenessNotes,
				LastUpdated:        remediation.LastUpdated,
			}
			doRemediations = append(doRemediations, cweRemediation)
		}
	}
	return doRemediations
}

func (h *ScanHandlers) DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	id, err := GetIDInt32(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	isDeleted, err := h.scanScheduleService.DeleteScanScheduleByID(ctx, id)
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

// GetScanResultsByScanID returns information gathering results for a given scan ID.
// @Summary      GetScanResultsByScanID
// @Description  Retrieve information gathering results (e.g., whois, DNS, subdomains, etc.) for a given scan ID.
// @Tags         Scans
// @Produce      json
// @Param        id   path      string  true  "Scan ID"
// @Success      200  {object}  dto.ScanInformationGatheredDTO
// @Failure      400  {object}  api.APIError         "Invalid scan ID"
// @Failure      404  {object}  api.APIError         "Scan not found"
// @Failure      500  {object}  api.APIError         "Internal server error"
// @Security     BearerAuth
// @Router      /api/scans/{id}/information-gathered [get]
func (h *ScanHandlers) GetScanResultsByScanID(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	scanID, err := GetUUID(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: "Invalid scan ID"})
	}

	scanResults, err := h.scanService.GetInformationGatheredResults(ctx, scanID)
	if err != nil {
		slog.Error("Failed to get scan by ID",
			slog.String("scan_id", scanID.String()),
			slog.Any("error", err))
		if errors.Is(err, customerrors.ErrScanNotFound) {
			return api.WriteJSON(w, http.StatusNotFound, api.APIError{Error: fmt.Sprintf("Scan %s not found", scanID.String())})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}

	dtoScanResult := dto.ConvertScanResultDomToDtoScanInformationGathered(scanResults)
	return api.WriteJSON(w, http.StatusOK, dtoScanResult)
}

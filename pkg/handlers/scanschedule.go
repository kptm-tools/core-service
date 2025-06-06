package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
)

type ScanScheduleHandlers struct {
	scanScheduleService interfaces.IScanScheduleService
	eventBus            cmmn.EventBus
}

var _ interfaces.IScanScheduleHandlers = (*ScanScheduleHandlers)(nil)

func NewScanScheduleHandlers(scanScheduleService interfaces.IScanScheduleService) *ScanScheduleHandlers {
	return &ScanScheduleHandlers{
		scanScheduleService: scanScheduleService,
	}
}

func (h *ScanScheduleHandlers) DeleteScanSchedule(w http.ResponseWriter, r *http.Request) error {
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

func (h *ScanScheduleHandlers) PatchScanSchedule(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	id, err := GetIDInt32(r)
	tenantID := ctx.Value(middleware.ContextTenantID).(uuid.UUID)
	userID := ctx.Value(middleware.ContextUserID).(uuid.UUID)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	updateScanScheduleRequest := new(dto.ScanScheduleRequest)

	if err := decodeJSONBody(w, r, updateScanScheduleRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	parsedToDate, parseErr := time.Parse("2006-01-02T15:04:05.000Z", *updateScanScheduleRequest.ScheduleAt)
	if parseErr != nil {
		slog.Error("Failed to parse schedule_at to Date UTC format",
			slog.String("schedule_at", *updateScanScheduleRequest.ScheduleAt),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid schedule_at field. Must follow Date UTC format e.g: '2025-02-26T20:57:51.000Z'",
		})
	}

	now := time.Now().UTC()
	twoMinuteLater := now.Add(2 * time.Minute)
	if !parsedToDate.After(twoMinuteLater) {
		slog.Warn("ScanSchedule rejected, must be at least 2 minutes greater than current time",
			slog.String("current_time", now.Format(time.DateTime)),
			slog.String("two_minutes_later", twoMinuteLater.Format(time.DateTime)))

		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid schedule_at field. Must be at least 2 minutes greater than the current time",
		})
	}
	hostID, errGetHostID := h.scanScheduleService.GetCurrentHostID(ctx, id)
	if errGetHostID != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: "There is no host configured configured for this scan schedule",
		})
	}
	errUpdate := h.scanScheduleService.PatchScanSchedule(ctx, id, updateScanScheduleRequest.Frequency, parsedToDate, tenantID, userID, hostID)
	if errUpdate != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Update can not be terminated because of " + errUpdate.Error(),
		})
	}
	return api.WriteJSON(w, http.StatusCreated, nil)
}

func (h *ScanScheduleHandlers) GetScanSchedules(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	tenantID, ok := r.Context().Value(middleware.ContextTenantID).(uuid.UUID)
	if !ok {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: http.StatusText(http.StatusInternalServerError)})
	}
	scanSchedules, errGetData := h.scanScheduleService.GetScanSchedulesByTenantID(ctx, tenantID)
	if errGetData != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "tenantID does not exist",
		})
	}
	return api.WriteJSON(w, http.StatusOK, scanSchedules)
}

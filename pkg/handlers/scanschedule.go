package handlers

import (
	"errors"
	"github.com/google/uuid"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"log/slog"
	"net/http"
	"time"
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

func (h *ScanScheduleHandlers) PatchScanSchedule(w http.ResponseWriter, r *http.Request) error {
	id, err := GetID(r)
	tenantID := r.Context().Value(middleware.ContextTenantID).(string)
	userID := r.Context().Value(middleware.ContextUserID).(string)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, err.Error())
	}

	updateScanScheduleRequest := new(ScanScheduleRequest)

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
		slog.Error("Failed to parse schedule_at to DateOnly format",
			slog.String("schedule_at", *updateScanScheduleRequest.ScheduleAt),
			slog.Any("error", err))
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid schedule_at field. Must follow DateOnly format e.g: '2025-02-26T20:57:51.000Z'",
		})
	}

	now := time.Now().UTC()
	twoMinuteLater := now.Add(2 * time.Minute)
	if !parsedToDate.After(twoMinuteLater) {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "Invalid schedule_at field. Must be at least 2 minutes greater than the current time",
		})
	}
	hostID, errGetHostID := h.scanScheduleService.GetCurrentHostID(id)
	if errGetHostID != nil {
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{
			Error: "There is no host configured configured for this scan schedule",
		})
	}
	errUpdate := h.scanScheduleService.PatchScanSchedule(id, updateScanScheduleRequest.Frequency, parsedToDate, tenantID, userID, hostID)
	if errUpdate != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "ID to update does not exist",
		})
	}
	return api.WriteJSON(w, http.StatusCreated, nil)
}

func (h *ScanScheduleHandlers) GetScanSchedules(w http.ResponseWriter, r *http.Request) error {
	tenantID := r.Context().Value(middleware.ContextTenantID).(string)
	tenantUUID, errTenantID := uuid.Parse(tenantID)
	if errTenantID != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "ID is of tenant is not an UUID",
		})
	}
	scanSchedules, errGetData := h.scanScheduleService.GetScanSchedules(tenantUUID)
	if errGetData != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{
			Error: "TenantID does not exist",
		})
	}
	return api.WriteJSON(w, http.StatusOK, scanSchedules)
}

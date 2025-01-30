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

	"github.com/kptm-tools/common/common/enums"
	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/api"
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

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	for _, dataScan := range scans {
		scanStartedPayload := &cmmn.ScanStartedEvent{
			BaseEvent: cmmn.BaseEvent{
				ScanID:    dataScan.ID,
				Timestamp: dataScan.CreatedAt.UTC(),
			},
			Target: dataScan.Target,
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

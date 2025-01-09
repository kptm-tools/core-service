package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
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

func (s ScanHandlers) CreateScans(w http.ResponseWriter, req *http.Request) error {

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

	scan, err := s.scanService.CreateScans(hostIDs)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			statusCode := http.StatusNotFound
			return api.WriteJSON(w, statusCode, api.APIError{Error: http.StatusText(statusCode)})
		}

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}

	scanStartedPayload := &cmmn.ScanStartedEvent{
		ScanID:    scan.ID,
		Targets:   scan.Targets,
		Timestamp: scan.CreatedAt.Unix(),
	}
	scanStartedBytes, err := json.Marshal(scanStartedPayload)
	s.eventBus.Publish("ScanStarted", scanStartedBytes)

	if err != nil {

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	return api.WriteJSON(w, http.StatusCreated, scan)
}

package handlers

import (
	"encoding/json"
	"errors"
	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"net/http"
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

	scan, err := s.scanService.CreateScans(scanRequest.HostIds)
	scanStartedPayload := &cmmn.ScanStartedEvent{
		ScanID:    scan.ID,
		Targets:   scan.Targets,
		Timestamp: scan.CreatedAt.Unix(),
	}
	scanStartedString, err := json.Marshal(scanStartedPayload)
	s.eventBus.Publish("ScanStarted", scanStartedString)

	if err != nil {

		return api.WriteJSON(w, http.StatusInternalServerError, err.Error())
	}
	return api.WriteJSON(w, http.StatusCreated, scan)
}

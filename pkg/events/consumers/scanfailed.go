package consumers

import (
	"encoding/json"
	"log/slog"

	"github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type ScanFailedHandler struct {
	scanService interfaces.IScanService
}

func NewScanFailedHandler(scanService interfaces.IScanService) *ScanFailedHandler {
	return &ScanFailedHandler{scanService: scanService}
}

var _ interfaces.EventConsumer = (*ScanFailedHandler)(nil)

func (h *ScanFailedHandler) HandleMessage(msg *nats.Msg) {
	go func(msg *nats.Msg) {
		slog.Info("Received ScanFailedEvent")

		// 1. Parse payload
		var evt events.ScanFailedEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Error("Failed to unmarshal ScanFailedEvent", slog.Any("error", err))
			return
		}

		// 2. Log the reason
		slog.Info("Scan failed",
			slog.String("scan_id", evt.ScanID.String()),
			slog.String("reason", evt.Reason))

		// 3. Update the scan's status on DB
		if err := h.scanService.MarkScanAsFailed(evt.ScanID); err != nil {
			slog.Error("Failed to update scan status",
				slog.String("scan_id", evt.ScanID.String()),
				slog.Any("error", err))
			return
		}

		slog.Debug("ScanFailedEvent handled successfully")

	}(msg)
}

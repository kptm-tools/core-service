package consumers

import (
	"encoding/json"
	"log/slog"

	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type NmapHandler struct {
	scanService interfaces.IScanService
}

func NewNmapHandler(scanService interfaces.IScanService) *NmapHandler {
	return &NmapHandler{scanService: scanService}
}

var _ interfaces.EventConsumer = (*NmapHandler)(nil)

func (h *NmapHandler) HandleMessage(msg *nats.Msg) {
	go func(msg *nats.Msg) {
		slog.Info("Received NmapEvent")

		// 1. Parse payload
		var evt events.ToolResultEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Error("Failed to unmarshal ToolResultEvent", slog.Any("error", err))
			return
		}

		// 2. Validate contents
		if evt.ToolResult.Tool != enums.ToolNmap {
			slog.Error("Invalid toolName for NmapEvent",
				slog.String("tool_name", string(evt.ToolResult.Tool)))
			return
		}

		scanResult := domain.NewScanResult(evt.ScanID, evt.ToolResult)

		// 2.1 Check for errors in the result
		if evt.ToolResult.Err != nil {
			slog.Warn("ToolResult contains an error, only storing ToolResult",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", evt.ToolResult.Err))

			// 3.1 Only store ToolResult, not Vulnerabilities
			if err := h.scanService.InsertScanResult(scanResult); err != nil {
				slog.Error("Error inserting ScanResult to DB",
					slog.String("scan_id", evt.ScanID.String()),
					slog.String("tool_name", string(evt.ToolResult.Tool)),
					slog.Any("error", err),
				)
				slog.Debug("NmapResult saved successfully")
				return
			}
		} else {
			// 3.2 Begin DB transaction to store ToolResult and Vulnerabilities
			if err := h.scanService.InsertVulnerabilityResult(scanResult); err != nil {
				slog.Error("Error inserting VulnerabilityResult to DB",
					slog.String("scan_id", evt.ScanID.String()),
					slog.String("tool_name", string(evt.ToolResult.Tool)),
					slog.Any("error", err))
			}
		}

		slog.Debug("NmapEvent handled successfully")

	}(msg)
}

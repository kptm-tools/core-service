package consumers

import (
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type WhoIsHandler struct {
	scanService interfaces.IScanService
}

func NewWhoIsHandler(scanService interfaces.IScanService) *WhoIsHandler {
	return &WhoIsHandler{scanService: scanService}
}

func (h *WhoIsHandler) HandleMessage(msg *nats.Msg) {
	go func(msg *nats.Msg) {
		slog.Info("Received WhoIsEvent")

		// 1. Parse payload
		var evt events.ToolResultEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Error("Failed to unmarshal ToolResultEvent", slog.Any("error", err))
			return
		}

		// 2. Validate contents
		if evt.ToolResult.Tool != enums.ToolWhoIs {
			slog.Error("Invalid toolName for WhoIsEvent",
				slog.String("scan_id", evt.ScanID),
				slog.String("tool_name", string(evt.ToolResult.Tool)))
			return
		}

		// 2.1 Check for errors in the result
		if evt.ToolResult.Err != nil {
			slog.Warn("ToolResult contains an error",
				slog.String("scan_id", evt.ScanID),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", evt.ToolResult.Err),
			)
		}

		// 3. Save ToolResult to DB
		scanID, err := uuid.Parse(evt.ScanID)
		if err != nil {
			slog.Error("ScanID is invalid UUID",
				slog.String("scan_id", evt.ScanID),
				slog.Any("error", err))
		}

		scanResult := domain.NewScanResult(scanID, evt.ToolResult)
		if err := h.scanService.InsertScanResult(scanResult); err != nil {
			slog.Error("Error inserting ScanResult to DB",
				slog.String("scan_id", evt.ScanID),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", err))
		}

		slog.Debug("WhoIsEvent saved successfully")

	}(msg)
}

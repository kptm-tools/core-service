package consumers

import (
	"encoding/json"
	eventsCore "github.com/kptm-tools/core-service/pkg/utils/events"
	"log/slog"

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

var _ interfaces.EventConsumer = (*WhoIsHandler)(nil)

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
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)))
			return
		}

		// 2.1 Check for errors in the result
		if evt.ToolResult.Err != nil {
			slog.Warn("ToolResult contains an error",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", evt.ToolResult.Err),
			)
		}

		actualScan, errScan := h.scanService.GetScanByID(evt.ScanID)
		if errScan != nil {
			slog.Error("Failed to get Scan", slog.String("scan_id", evt.ScanID.String()))
			return
		}
		if eventsCore.CanInsertScanResult(actualScan.Status) {
			slog.Error("Error inserting ScanResult to DB because of Scan Status",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("Status ", actualScan.Status),
			)
			return
		}
		// 3. Save ToolResult to DB

		scanResult := domain.NewScanResult(evt.ScanID, evt.ToolResult)
		if err := h.scanService.InsertScanResult(scanResult); err != nil {
			slog.Error("Error inserting ScanResult to DB",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", err))
			return
		}

		slog.Debug("WhoIsEvent handled successfully")

	}(msg)
}

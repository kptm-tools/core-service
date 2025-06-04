package consumers

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
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
		ctx := context.Background()
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

		// 2.1 Check if the current scan status is still healthy
		actualScan, errScan := h.scanService.GetScanByID(ctx, evt.ScanID)
		if errScan != nil {
			slog.Error("Failed to get Scan", slog.String("scan_id", evt.ScanID.String()))
			return
		}
		if actualScan.IsFailedOrCancelled() {
			slog.Error("Error inserting ScanResult to DB because of Scan Status",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("Status ", actualScan.Status),
			)
			return
		}

		// 2.2 Check for errors in the result
		handleToolResultError(ctx, evt.ScanID, evt.ToolResult, h.scanService)

		// 3. Save ToolResult to DB

		scanResult := domain.NewScanResult(evt.ScanID, evt.ToolResult)
		if err := h.scanService.InsertScanResult(ctx, *scanResult); err != nil {
			slog.Error("Error inserting ScanResult to DB",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", err))
			return
		}

		slog.Debug("WhoIsEvent handled successfully")
	}(msg)
}

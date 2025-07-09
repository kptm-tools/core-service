package consumers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type WebScanHandler struct {
	scanService interfaces.IScanService
	vulnService interfaces.IVulnerabilityService
}

func NewWebScanHandler(
	scanService interfaces.IScanService,
	vulnerabilityService interfaces.IVulnerabilityService,
) *WebScanHandler {
	return &WebScanHandler{
		scanService: scanService,
		vulnService: vulnerabilityService,
	}
}

var _ interfaces.EventConsumer = (*WebScanHandler)(nil)

func (h *WebScanHandler) HandleMessage(msg *nats.Msg) {
	go func(msg *nats.Msg) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic recovered in WebScanHandler", "panic", r, "stack", string(debug.Stack()))
			}
		}()
		slog.Info("Received WebScanEvent")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// 1. Parse payload
		var evt events.ToolResultEvent
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			slog.Error("Failed to unmarshal ToolResultEvent", slog.Any("error", err))
			return
		}

		// 2. Validate contents
		if evt.ToolResult.Tool != enums.ToolWebScan {
			slog.Error("Invalid toolName for WebScanEvent",
				slog.String("tool_name", string(evt.ToolResult.Tool)))
			return
		}
		scan, errScan := h.scanService.GetScanByID(ctx, evt.ScanID)
		if errScan != nil {
			slog.Error("Failed to get Scan", slog.String("scan_id", evt.ScanID.String()))
			return
		}
		if scan.IsFailedOrCancelled() {
			slog.Error("Error inserting ScanResult to DB because of Scan Status",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("current_status ", scan.Status),
			)
			return
		}
		scanResult := domain.NewScanResult(evt.ScanID, evt.ToolResult)

		// 3.1 Only store ToolResult, not Vulnerabilities
		if err := h.scanService.InsertScanResult(ctx, *scanResult); err != nil {
			slog.Error("Error inserting ScanResult to DB",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", err),
			)

			// Mark the scan as failed
			if err := h.scanService.MarkScanAsFailed(ctx, evt.ScanID); err != nil {
				slog.Error("Error marking scan as failed",
					slog.String("scan_id", evt.ScanID.String()),
					slog.Any("error", err))
			}

			slog.Debug("Scan marked as failed successfully", slog.String("scan_id", evt.ScanID.String()))

			return
		}

		// 2.1 Check for errors in the result
		if evt.ToolResult.Err != nil {
			slog.Warn("ToolResult contains an error, only storing ToolResult",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", evt.ToolResult.Err))

			if err := h.scanService.MarkScanAsFailed(ctx, evt.ScanID); err != nil {
				slog.Error("Error marking scan as failed",
					slog.String("scan_id", evt.ScanID.String()),
					slog.Any("error", err))
				return
			}
			slog.Debug("Scan marked as failed successfully", slog.String("scan_id", evt.ScanID.String()))
			return
		}

		// 3.1 Parse the vulnerabilities from the result
		// 3.1.1 Unmarshal the result to a tools.NmapResult variable
		var nr tools.WebScanResult
		resultPtr, ok := scanResult.Result.Result.(*tools.WebScanResult)
		if !ok || resultPtr == nil {
			slog.Error(
				"Failed to assert webScan result type", // Static, searchable message
				"scan_id", scan.ID.String(),            // Structured context
				"expected_type", "*tools.WebScanResult",
				"actual_type", fmt.Sprintf("%T", scanResult.Result.Result),
			)
		}
		nr = *resultPtr

		// 3.2 Pass the webScan result to the VulnService InsertWebScanVulnerabilities method

		if err := h.vulnService.InsertWebScanVulnerabilities(ctx, scan.ID, nr); err != nil {
			slog.Error(
				"Error inserting VulnerabilityResult to DB (WebVulnerabillities)",
				slog.String("scan_id", evt.ScanID.String()),
				slog.String("tool_name", string(evt.ToolResult.Tool)),
				slog.Any("error", err))

			// Mark the scan as failed
			if err := h.scanService.MarkScanAsFailed(ctx, evt.ScanID); err != nil {
				slog.Error("Error marking scan as failed",
					slog.String("scan_id", evt.ScanID.String()),
					slog.Any("error", err))
				return
			}
			return
		}

		slog.Debug("WebScanEvent handled successfully")
	}(msg)
}

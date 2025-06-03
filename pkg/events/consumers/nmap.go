package consumers

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type NmapHandler struct {
	scanService interfaces.IScanService
	vulnService interfaces.IVulnerabilityService
}

func NewNmapHandler(
	scanService interfaces.IScanService,
	vulnerabilityService interfaces.IVulnerabilityService,
) *NmapHandler {
	return &NmapHandler{
		scanService: scanService,
		vulnService: vulnerabilityService,
	}
}

var _ interfaces.EventConsumer = (*NmapHandler)(nil)

func (h *NmapHandler) HandleMessage(msg *nats.Msg) {
	go func(msg *nats.Msg) {
		ctx := context.Background()
		slog.Info("Received NmapEvent")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

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
		slog.Debug("Nmap ToolResult saved successfully")

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
		var nr tools.NmapResult
		resultPtr, ok := scanResult.Result.Result.(*tools.NmapResult)
		if !ok || resultPtr == nil {
			slog.Error(
				"Failed to assert nmap result to tools.NmapResult; actual type: %T", scanResult.Result.Result,
				slog.String("scan_id", scan.ID.String()),
			)
		}
		nr = *resultPtr

		// 3.2 Pass the nmap result to the VulnService InsertNetworkOSVulnerability method

		// 3.2 Begin DB transaction to store ToolResult and Vulnerabilities
		if err := h.vulnService.CreateNetworkOSVulnerabilities(ctx, scan.ID, nr); err != nil {
			slog.Error(
				"Error inserting VulnerabilityResult to DB",
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

		slog.Debug("NmapEvent handled successfully")
	}(msg)
}

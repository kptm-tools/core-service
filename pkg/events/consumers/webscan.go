package consumers

import (
	"context"
	"encoding/json"
	"errors"
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
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in NmapHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received WebScanEvent")
	ctx, cancel := context.WithTimeout(context.Background(), 3600*time.Second)
	defer cancel()
	go h.processWebScanEventRoutine(ctx, msg.Data)
	<-ctx.Done()
}

func (h *WebScanHandler) processWebScanEventRoutine(ctx context.Context, data []byte) {
	select {
	case <-ctx.Done():
		slog.Debug("NmapHandler context cancelled or timed out", slog.Any("error", ctx.Err()))
	default:
		err := h.processWebScanEvent(ctx, data)
		if err != nil {
			slog.Debug("Error processing WebScanEvent", "error", err)
		}
	}
}

func (h *WebScanHandler) processWebScanEvent(ctx context.Context, data []byte) error {
	// 1. Parse payload
	var evt events.ToolResultEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		slog.Error("Failed to unmarshal ToolResultEvent", slog.Any("error", err))
		return err
	}

	// 2. Validate contents
	if evt.ToolResult.Tool != enums.ToolWebScan {
		slog.Error("Invalid toolName for WebScanEvent",
			slog.String("tool_name", string(evt.ToolResult.Tool)))
		return errors.New("invalid toolName for WebScanEvent")
	}
	scan, errScan := h.scanService.GetScanByID(ctx, evt.ScanID)
	if errScan != nil {
		slog.Error("Failed to get Scan", slog.String("scan_id", evt.ScanID.String()))
		return errScan
	}
	if scan.IsFailedOrCancelled() {
		slog.Error("Error inserting ScanResult to DB because of Scan Status",
			slog.String("scan_id", evt.ScanID.String()),
			slog.String("tool_name", string(evt.ToolResult.Tool)),
			slog.Any("current_status ", scan.Status),
		)
		return errors.New("error inserting ScanResult to DB because of Scan Status")
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

		return err
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
			return err
		}
		slog.Debug("Scan marked as failed successfully", slog.String("scan_id", evt.ScanID.String()))
		return errors.New("error in tool result")
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
		return errors.New("failed to assert webScan result type")
	}
	nr = *resultPtr

	// 3.2 Pass the webScan result to the VulnService InsertWebScanVulnerabilities method

	if err := h.vulnService.InsertWebScanVulnerabilities(ctx, scan.ID, nr); err != nil {
		slog.Error(
			"Error inserting VulnerabilityResult to DB (WebVulnerabilities)",
			slog.String("scan_id", evt.ScanID.String()),
			slog.String("tool_name", string(evt.ToolResult.Tool)),
			slog.Any("error", err))

		// Mark the scan as failed
		if err := h.scanService.MarkScanAsFailed(ctx, evt.ScanID); err != nil {
			slog.Error("Error marking scan as failed",
				slog.String("scan_id", evt.ScanID.String()),
				slog.Any("error", err))
			return err
		}
		return err
	}
	slog.Debug("WebScanEvent handled successfully")
	return nil
}

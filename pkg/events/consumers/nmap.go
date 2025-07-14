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
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in NmapHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received NmapEvent")
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()
	go h.processNmapEventRoutine(ctx, msg.Data)
	<-ctx.Done()
}

func (h *NmapHandler) processNmapEventRoutine(ctx context.Context, data []byte) {
	select {
	case <-ctx.Done():
		slog.Debug("NmapHandler context cancelled or timed out", slog.Any("error", ctx.Err()))
	default:
		err := h.processNmapEvent(ctx, data)
		if err != nil {
			slog.Debug("Error processing NmapEvent", "error", err)
		}
	}
}

func (h *NmapHandler) processNmapEvent(ctx context.Context, data []byte) error {
	// 1. Parse payload
	var evt events.ToolResultEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		slog.Error("Failed to unmarshal ToolResultEvent", slog.Any("error", err))
		return err
	}

	// 2. Validate contents
	if evt.ToolResult.Tool != enums.ToolNmap {
		slog.Error("Invalid toolName for NmapEvent",
			slog.String("tool_name", string(evt.ToolResult.Tool)))
		return errors.New("invalid toolName for NmapEvent")
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
			return err
		}
		slog.Debug("Scan marked as failed successfully", slog.String("scan_id", evt.ScanID.String()))
		return evt.ToolResult.Err
	}

	// 3.1 Parse the vulnerabilities from the result
	// 3.1.1 Unmarshal the result to a tools.NmapResult variable
	var nr tools.NmapResult
	resultPtr, ok := scanResult.Result.Result.(*tools.NmapResult)
	if !ok || resultPtr == nil {
		slog.Error(
			"Failed to assert nmap result type", // Static, searchable message
			"scan_id", scan.ID.String(),         // Structured context
			"expected_type", "*tools.NmapResult",
			"actual_type", fmt.Sprintf("%T", scanResult.Result.Result),
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
			return err
		}
		return err
	}
	slog.Debug("NmapEvent handled successfully")
	return nil
}

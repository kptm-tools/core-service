package consumers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type HarvesterHandler struct {
	scanService interfaces.IScanService
}

func NewHarvesterHandler(scanService interfaces.IScanService) *HarvesterHandler {
	return &HarvesterHandler{scanService: scanService}
}

var _ interfaces.EventConsumer = (*HarvesterHandler)(nil)

func (h *HarvesterHandler) HandleMessage(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in HarvesterHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received HarvesterEvent")
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()
	go h.processHarvesterEventRoutine(ctx, msg.Data)
	<-ctx.Done()
}

func (h *HarvesterHandler) processHarvesterEventRoutine(ctx context.Context, data []byte) {
	select {
	case <-ctx.Done():
		slog.Debug("HarvesterHandler context cancelled or timed out", slog.Any("error", ctx.Err()))
	default:
		err := h.processHarvesterEvent(ctx, data)
		if err != nil {
			slog.Debug("Error processing HarvesterEvent", "error", err)
		}
	}
}

func (h *HarvesterHandler) processHarvesterEvent(ctx context.Context, data []byte) error {

	// 1. Parse payload
	var evt events.ToolResultEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		slog.Error("Failed to unmarshal ToolResultEvent",
			slog.String("tool_name", string(evt.ToolResult.Tool)),
			slog.Any("error", err))
		return err
	}

	// 2. Validate contents
	if evt.ToolResult.Tool != enums.ToolHarvester {
		slog.Error("Invalid toolName for HarvesterEvent",
			slog.String("scan_id", evt.ScanID.String()),
			slog.String("tool_name", string(evt.ToolResult.Tool)))
		return errors.New("invalid toolName for HarvesterEvent")
	}

	// 2.1 Check if the current scan status is still healthy
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
		return errors.New("error inserting ScanResult to DB of Scan Status")
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
		return err
	}

	slog.Debug("HarvesterEvent handled successfully")
	return nil
}

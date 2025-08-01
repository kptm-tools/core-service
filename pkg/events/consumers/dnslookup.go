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

type DNSLookupHandler struct {
	scanService interfaces.IScanService
}

func NewDNSLookupHandler(scanService interfaces.IScanService) *DNSLookupHandler {
	return &DNSLookupHandler{scanService: scanService}
}

var _ interfaces.EventConsumer = (*DNSLookupHandler)(nil)

func (h *DNSLookupHandler) HandleMessage(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in DNSLookupHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received DNSLookupEvent")
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()
	go h.processDNSLookupEventRoutine(ctx, msg.Data)
	<-ctx.Done()
}

func (h *DNSLookupHandler) processDNSLookupEventRoutine(ctx context.Context, data []byte) {
	select {
	case <-ctx.Done():
		slog.Debug("DNSLookupHandler context cancelled or timed out", slog.Any("error", ctx.Err()))
	default:
		err := h.processDNSLookupEvent(ctx, data)
		if err != nil {
			slog.Debug("Error processing DNSLookupEvent", "error", err)
		}
	}
}

func (h *DNSLookupHandler) processDNSLookupEvent(ctx context.Context, data []byte) error {
	// 1. Parse payload
	var evt events.ToolResultEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		slog.Error("Failed to unmarshal ToolResultEvent", slog.Any("error", err))
		return err
	}

	// 2. Validate contents
	if evt.ToolResult.Tool != enums.ToolDNSLookup {
		slog.Error("Invalid toolName for DNSLookupEvent", slog.String("tool_name", string(evt.ToolResult.Tool)))
		return errors.New("invalid toolName for DNSLookupEvent")
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
		return errors.New("cannot insert scan result: scan is failed or cancelled")
	}

	// 2.2 Check for errors in the result
	handleToolResultError(ctx, evt.ScanID, evt.ToolResult, h.scanService)

	// 3. Save ToolResult to DB
	scanResult := domain.NewScanResult(evt.ScanID, evt.ToolResult)

	if err := h.scanService.InsertScanResult(ctx, *scanResult); err != nil {
		slog.Error("Error inserting ScanResult to DB",
			slog.String("scan_id", evt.ScanID.String()),
			slog.String("tool_name", string(evt.ToolResult.Tool)),
			slog.Any("error", err),
		)
		return err
	}

	slog.Debug("DNSLookupEvent handled successfully")
	return nil
}

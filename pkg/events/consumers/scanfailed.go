package consumers

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type ScanFailedHandler struct {
	scanService interfaces.IScanService
}

func NewScanFailedHandler(scanService interfaces.IScanService) *ScanFailedHandler {
	return &ScanFailedHandler{scanService: scanService}
}

var _ interfaces.EventConsumer = (*ScanFailedHandler)(nil)

func (h *ScanFailedHandler) HandleMessage(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in ScanFailedHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received ScanFailedEvent")
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
	defer cancel()
	go h.processScanFailedEventRoutine(ctx, msg.Data)
	<-ctx.Done()
}

func (h *ScanFailedHandler) processScanFailedEventRoutine(ctx context.Context, data []byte) {
	select {
	case <-ctx.Done():
		slog.Debug("ScanFailedHandler context cancelled or timed out", slog.Any("error", ctx.Err()))
	default:
		err := h.processScanFailedEvent(ctx, data)
		if err != nil {
			slog.Debug("Error processing ScanFailedEvent", "error", err)
		}
	}
}

func (h *ScanFailedHandler) processScanFailedEvent(ctx context.Context, data []byte) error {
	// 1. Parse payload
	var evt events.ScanFailedEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		slog.Error("Failed to unmarshal ScanFailedEvent", slog.Any("error", err))
		return err
	}

	// 2. Log the reason
	slog.Info("Scan failed",
		slog.String("scan_id", evt.ScanID.String()),
		slog.String("reason", evt.Reason))

	// 3. Update the scan's status on DB
	if err := h.scanService.MarkScanAsFailed(ctx, evt.ScanID); err != nil {
		slog.Error("Failed to update scan status",
			slog.String("scan_id", evt.ScanID.String()),
			slog.Any("error", err))
		return err
	}
	return nil
}

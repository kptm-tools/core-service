package consumers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type HarvesterHandler struct {
	scanService interfaces.IScanService
	workers     int            // number of workers
	queue       chan *nats.Msg // jobQueue

	// Metrics
	// processed: Number of events successfully processed by the handler
	processed atomic.Uint64
	// failed: Number of events that failed during processing
	failed atomic.Uint64
	// dropped: Number of events dropped due to full queue/backpressure
	dropped atomic.Uint64
	// queueDepth: Current number of events waiting in the queue
	queueDepth atomic.Int32
}

func NewHarvesterHandler(scanService interfaces.IScanService, workers int) *HarvesterHandler {
	bufferSize := workers * 2
	handler := &HarvesterHandler{
		scanService: scanService,
		workers:     workers,
		queue:       make(chan *nats.Msg, bufferSize), //  **BUFFERED** channel to avoid blocking
	}
	handler.startWorkers()
	return handler
}

var _ interfaces.EventConsumer = (*HarvesterHandler)(nil)

// startWorkers launch all goroutines for workers, these are there until new work arrive
func (h *HarvesterHandler) startWorkers() {
	for i := 0; i < h.workers; i++ {
		go func() {
			for msg := range h.queue {
				// Update queue depth metric
				h.queueDepth.Add(-1)
				// processing logic
				ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
				err := h.processHarvesterEvent(ctx, msg.Data)
				cancel()

				if err != nil {
					h.failed.Add(1)
					slog.Error("HarvesterHandler incrementing FAILED metric")
				} else {
					h.processed.Add(1)
					slog.Debug("HarvesterHandler incrementing PROCESSED metric")
				}
			}
		}()
	}
}

func (h *HarvesterHandler) HandleMessage(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in HarvesterHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received HarvesterEvent")
	// Try to send to job queue with timeout
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case h.queue <- msg:
		h.queueDepth.Add(1)
	case <-timer.C:
		// Queue is full, drop the message and increment dropped metric
		h.dropped.Add(1)
		slog.Warn("HarvesterEvent queue full, dropping message")
	}
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
			slog.Any("error", err))
		return err
	}

	slog.Debug("HarvesterEvent handled successfully")
	return nil
}

// GetMetrics getters for monitoring
func (h *HarvesterHandler) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"processed":    h.processed.Load(),
		"failed":       h.failed.Load(),
		"dropped":      h.dropped.Load(),
		"queue_depth":  h.queueDepth.Load(),
		"worker_count": h.workers,
	}
}

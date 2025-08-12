package consumers

import (
	"context"
	"encoding/json"
	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
	"log/slog"
	"runtime/debug"
	"sync/atomic"
	"time"
)

type ScanFailedHandler struct {
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

func NewScanFailedHandler(scanService interfaces.IScanService, workers int) *ScanFailedHandler {
	bufferSize := workers * 2
	handler := &ScanFailedHandler{
		scanService: scanService,
		workers:     workers,
		queue:       make(chan *nats.Msg, bufferSize), //  **BUFFERED** channel to avoid blocking
	}
	handler.startWorkers()
	return handler
}

var _ interfaces.EventConsumer = (*ScanFailedHandler)(nil)

// startWorkers launch all goroutines for workers, these are there until new work arrive
func (h *ScanFailedHandler) startWorkers() {
	for i := 0; i < h.workers; i++ {
		go func() {
			for msg := range h.queue {
				// Update queue depth metric
				h.queueDepth.Add(-1)
				// processing logic
				ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
				err := h.processScanFailedEvent(ctx, msg.Data)
				cancel()

				if err != nil {
					h.failed.Add(1)
					slog.Error("ScanFailedHandler incrementing FAILED metric")
				} else {
					h.processed.Add(1)
					slog.Debug("ScanFailedHandler incrementing PROCESSED metric")
				}
			}
		}()
	}
}

func (h *ScanFailedHandler) HandleMessage(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in ScanFailedHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	slog.Info("Received ScanFailedEvent")
	// Try to send to job queue with timeout
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case h.queue <- msg:
		h.queueDepth.Add(1)
	case <-timer.C:
		// Queue is full, drop the message and increment dropped metric
		h.dropped.Add(1)
		slog.Warn("ScanFailedEvent queue full, dropping message")
	}
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

// GetMetrics getters for monitoring
func (h *ScanFailedHandler) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"processed":    h.processed.Load(),
		"failed":       h.failed.Load(),
		"dropped":      h.dropped.Load(),
		"queue_depth":  h.queueDepth.Load(),
		"worker_count": h.workers,
	}
}

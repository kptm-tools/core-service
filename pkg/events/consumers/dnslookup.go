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

// DNSLookupHandler struct con un canal de worker pool
type DNSLookupHandler struct {
	scanService interfaces.IScanService
	workers     int            // Número de workers
	queue       chan *nats.Msg // La cola de trabajo

	// Metrics
	processed  atomic.Uint64
	failed     atomic.Uint64
	dropped    atomic.Uint64
	queueDepth atomic.Int32
}

// NewDNSLookupHandler ahora toma como argumento el numero de workers
func NewDNSLookupHandler(scanService interfaces.IScanService, workers int) *DNSLookupHandler {
	handler := &DNSLookupHandler{
		scanService: scanService,
		workers:     workers,
		queue:       make(chan *nats.Msg, workers), // Ojo que es un canal **BUFFERED** para evitar bloqueos
	}
	handler.startWorkers()
	return handler
}

var _ interfaces.EventConsumer = (*DNSLookupHandler)(nil)

// startWorkers lanza todas las corutinas de los workers.
// Estos se quedan "esperando" a que les llegue trabajo!
func (h *DNSLookupHandler) startWorkers() {
	for i := 0; i < h.workers; i++ {
		go func() {
			for msg := range h.queue {
				// ... lógica de procesamiento (igualito al processDNSLookupEventRoutine de antes)
				ctx, cancel := context.WithTimeout(context.Background(), 900*time.Second)
				err := h.processDNSLookupEvent(ctx, msg.Data)
				cancel()

				if err != nil {
					h.failed.Add(1)
					slog.Error("Error processing DNSLookupEvent", "error", err)
				} else {
					h.processed.Add(1)
					slog.Debug("DNSLookupEvent handled successfully")
				}
			}
		}()
	}
}

// HandleMessage add work to the queue, from which works are always listening.
func (h *DNSLookupHandler) HandleMessage(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in DNSLookupHandler", "panic", r, "stack", string(debug.Stack()))
		}
	}()

	h.queue <- msg
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

// GetMetrics getters for monitoring
func (h *DNSLookupHandler) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"processed":   h.processed.Load(),
		"failed":      h.failed.Load(),
		"dropped":     h.dropped.Load(),
		"queuedepth":  h.queueDepth.Load(),
		"workercount": h.workers,
	}
}

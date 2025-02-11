package storage

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/lib/pq"
)

type PostgresListener struct {
	listener    *pq.Listener
	scanService interfaces.IScanService
}

func NewPostgresListener(
	cfg *config.Config,
	scanService interfaces.IScanService,
) (*PostgresListener, error) {
	connectionString := cfg.PostgreSQLCoreConnStr()
	listener := pq.NewListener(connectionString,
		10*time.Second,
		1*time.Minute,
		func(event pq.ListenerEventType, err error) {
			if err != nil {
				slog.Error("Postgres listener event",
					slog.Any("event", event), slog.Any("error", err))
			} else {
				slog.Info("Postgres listener event",
					slog.Any("event", event))
			}
		},
	)

	// Listen to scan_completed channel
	if err := listener.Listen("scan_completed"); err != nil {
		return nil, fmt.Errorf("failed to listen to scan_completed channel: %w", err)
	}
	slog.Info("PostgresListener started", slog.String("channel", "scan_completed"))

	if err := listener.Listen("scan_cron"); err != nil {
		return nil, fmt.Errorf("failed to listen to scan_cron channel: %w", err)
	}
	slog.Info("PostgresListener started", slog.String("channel", "scan_cron"))
	postgresListener := &PostgresListener{
		listener:    listener,
		scanService: scanService,
	}

	go postgresListener.startListening()

	return postgresListener, nil
}

func (pl *PostgresListener) startListening() {
	for {
		notification := <-pl.listener.Notify

		slog.Debug("Received PostgresListener notification")

		// Parse the notification method
		var scanCompletedEvent events.BaseEvent
		if err := json.Unmarshal([]byte(notification.Extra), &scanCompletedEvent); err != nil {
			slog.Error("Failed to parse scan completed event",
				slog.Any("error", err),
				slog.Any("payload", notification.Extra))
			continue
		}

		slog.Debug("Parsed scan completed event", slog.String("scanID", scanCompletedEvent.ScanID.String()))
		// Use scanService to handle scanCompleted
		if err := pl.scanService.HandleScanCompletion(scanCompletedEvent.ScanID); err != nil {
			slog.Error("Failed to handle scan completion",
				slog.String("scanID", scanCompletedEvent.ScanID.String()),
				slog.Any("error", err))
		}

	}
}

func (pl *PostgresListener) Close() error {
	return pl.listener.Close()
}

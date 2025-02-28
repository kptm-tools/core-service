package storage

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"log/slog"
	"time"

	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/lib/pq"
)

type PostgresListener struct {
	listener    *pq.Listener
	eventBus    cmmn.EventBus
	scanService interfaces.IScanService
}

type ScanCron struct {
	ScanID         uuid.UUID `json:"scan_id"`
	HostID         int       `json:"host_id"`
	Timestamp      time.Time `json:"timestamp"`
	HasPeriod      bool      `json:"has_period"`
	ScanScheduleID int       `json:"scan_schedule_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	OperatorID     uuid.UUID `json:"operator_id"`
	NextSchedule   time.Time `json:"next_schedule"`
}

func NewPostgresListener(
	cfg *config.Config,
	scanService interfaces.IScanService,
	eventBus cmmn.EventBus,
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
		eventBus:    eventBus,
	}

	go postgresListener.startListening()

	return postgresListener, nil
}

func (pl *PostgresListener) startListening() {
	for {
		notification := <-pl.listener.Notify

		slog.Debug("Received PostgresListener notification")

		switch notification.Channel {
		case "scan_completed":
			{
				// Parse the notification method
				var scanCompletedEvent cmmn.BaseEvent
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
		case "scan_cron":
			// Parse the notification method
			var scanCron ScanCron
			if err := json.Unmarshal([]byte(notification.Extra), &scanCron); err != nil {
				slog.Error("Failed to parse scan cron event",
					slog.Any("error", err),
					slog.Any("payload", notification.Extra))
				continue
			}

			slog.Debug("Parsed scan cron event", slog.String("scanID", scanCron.ScanID.String()))

			// Create the target
			target, errTarget := pl.scanService.CreateTarget(scanCron.HostID)
			if errTarget != nil {
				slog.Error("Failed to create target", slog.Any("error", errTarget))
			}
			scanStartedPayload := &cmmn.ScanStartedEvent{
				BaseEvent: cmmn.BaseEvent{
					ScanID:    scanCron.ScanID,
					Timestamp: scanCron.Timestamp.UTC(),
				},
				Target: *target,
			}
			scanStartedBytes, err := json.Marshal(scanStartedPayload)
			if err != nil {
				slog.Error("Failed to marshal scan started event")
			}
			pl.eventBus.Publish(string(enums.ScanStartedEventSubject), scanStartedBytes)

			if !scanCron.HasPeriod {
				errDisable := pl.scanService.ScanScheduleDisableJob(scanCron.ScanScheduleID)
				if errDisable != nil {
					slog.Error("Failed to disable job of scan scheduling", slog.Any("error", errDisable))
				}
			} else {
				// 1. Create scan
				scan, errCreationScan := pl.scanService.CreateScan(scanCron.HostID, scanCron.TenantID.String(), scanCron.OperatorID.String(), &scanCron.NextSchedule)
				if errCreationScan != nil {
					slog.Error("Failed to create scans", slog.Any("error", err))
				}
				// 2. Update scan scheduling with new scanID
				errUpdateScanSchedule := pl.scanService.UpdateScanScheduleScanID(scan.ID, scanCron.ScanScheduleID)
				if errUpdateScanSchedule != nil {
					slog.Error("Failed to update scan_scheduling", slog.Any("error", err))
				}
			}
		}

	}
}

func (pl *PostgresListener) Close() error {
	return pl.listener.Close()
}

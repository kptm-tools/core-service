package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"

	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/utils"
	"github.com/lib/pq"
)

type PostgresListener struct {
	listener        *pq.Listener
	eventBus        cmmn.EventBus
	scanService     interfaces.IScanService
	scheduleService interfaces.IScanScheduleService
	emailService    interfaces.IEmailService
}

type ScanCron struct {
	ScanID         uuid.UUID `json:"scan_id"`
	HostID         uuid.UUID `json:"host_id"`
	Timestamp      time.Time `json:"timestamp"`
	HasPeriod      bool      `json:"has_period"`
	ScanScheduleID int       `json:"scan_schedule_id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	OperatorID     uuid.UUID `json:"operator_id"`
	NextSchedule   time.Time `json:"next_schedule"`
}

const (
	notificationEventTimeout = 10 * time.Minute
)

func NewPostgresListener(
	cfg *config.Config,
	scanService interfaces.IScanService,
	scheduleService interfaces.IScanScheduleService,
	emailService interfaces.IEmailService,
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
		listener:        listener,
		scanService:     scanService,
		scheduleService: scheduleService,
		emailService:    emailService,
		eventBus:        eventBus,
	}

	go postgresListener.startListening(context.Background())

	return postgresListener, nil
}

// startListening listens for notifications until the parent context is cancelled.
func (pl *PostgresListener) startListening(parentCtx context.Context) {
	const maxConcurrentNotifications = 10 // Adjust as needed
	semaphore := make(chan struct{}, maxConcurrentNotifications)
	for {
		select {
		case <-parentCtx.Done():
			slog.Info("PostgresListener: parent context cancelled, stopping listener loop")
			return
		case notification := <-pl.listener.Notify:
			semaphore <- struct{}{} // Acquire a slot
			slog.Debug("Received PostgresListener notification", slog.Any("notification", notification))
			// Each event gets its own context with timeout
			eventCtx, eventCancel := context.WithTimeout(parentCtx, notificationEventTimeout)
			go func(ctx context.Context, n *pq.Notification) {
				defer func() {
					<-semaphore
					eventCancel()
				}() // Ensure eventCancel happens before releasing the slot
				pl.handleNotification(ctx, n)

			}(eventCtx, notification)
		}
	}
}

func (pl *PostgresListener) handleNotification(ctx context.Context, notification *pq.Notification) {
	if notification != nil {
		switch notification.Channel {
		case "scan_completed":
			pl.handleScanCompletedNotification(ctx, notification.Extra)
		case "scan_cron":
			pl.handleScanCronNotification(ctx, notification.Extra)
		}
	}
}

func (pl *PostgresListener) Close() error {
	return pl.listener.Close()
}

func (pl *PostgresListener) handleScanCompletedNotification(ctx context.Context, payload string) error {
	// Parse the notification method
	var scanCompletedEvent cmmn.BaseEvent
	if err := json.Unmarshal([]byte(payload), &scanCompletedEvent); err != nil {
		slog.Error("Failed to parse scan completed event",
			slog.Any("error", err),
			slog.Any("payload", payload))
		return err
	}

	slog.Debug("Parsed scan completed event", slog.String("scanID", scanCompletedEvent.ScanID.String()))
	// Use scanService to handle scanCompleted
	if err := pl.scanService.HandleScanCompletion(ctx, scanCompletedEvent.ScanID); err != nil {
		slog.Error("Failed to handle scan completion",
			slog.String("scanID", scanCompletedEvent.ScanID.String()),
			slog.Any("error", err))
	}
	// 3. Get the emails rapporteurs structure
	rapporteurs, hostName, errGetRapporteur := pl.scanService.GetScanRapporteursAndHostAlias(ctx, scanCompletedEvent.ScanID)
	if errGetRapporteur != nil {
		slog.Error("Can not obtain rapporteurs associated to the scan",
			slog.String("scan_id", scanCompletedEvent.ScanID.String()),
			slog.Any("error", errGetRapporteur))
		return errGetRapporteur
	}

	for _, rapporteur := range rapporteurs {
		if err := pl.emailService.SendScanCompletedEmail(rapporteur.Email, hostName); err != nil {
			slog.Warn("Failed to send email to rapporteur",
				slog.String("scan_id", scanCompletedEvent.ScanID.String()),
				slog.String("rapporteur_email", rapporteur.Email),
				slog.Any("error", err),
			)
			continue
		}
	}
	return nil
}

func (pl *PostgresListener) handleScanCronNotification(ctx context.Context, payload string) error {
	// Parse the notification method
	var scanCron ScanCron
	if err := json.Unmarshal([]byte(payload), &scanCron); err != nil {
		slog.Error("Failed to parse scan cron event",
			slog.Any("error", err),
			slog.Any("payload", payload))
		return err
	}

	slog.Debug("Parsed scan cron event", slog.String("scanID", scanCron.ScanID.String()))

	// Create the target
	target, errTarget := pl.scanService.CreateTarget(ctx, scanCron.HostID)
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

	scheduleID, err := utils.SafeIntToInt32(scanCron.ScanScheduleID)
	if err != nil {
		return err
	}

	if !scanCron.HasPeriod {
		errDisable := pl.scheduleService.ScanScheduleDisableJob(ctx, scheduleID)
		if errDisable != nil {
			slog.Error("Failed to disable job of scan scheduling", slog.Any("error", errDisable))
		}
	} else {
		// 1. Create scan
		scan, errCreationScan := pl.scanService.CreateScan(
			ctx,
			scanCron.HostID,
			scanCron.TenantID,
			scanCron.OperatorID,
			&scanCron.NextSchedule,
		)
		if errCreationScan != nil {
			slog.Error("Failed to create scans", slog.Any("error", err))
			return errCreationScan
		}
		// 2. Update scan scheduling with new scanID
		errUpdateScanSchedule := pl.scheduleService.UpdateScanScheduleScanID(ctx, scan.ID, scheduleID)
		if errUpdateScanSchedule != nil {
			slog.Error("Failed to update scan_scheduling", slog.Any("error", err))
		}
	}
	return nil
}

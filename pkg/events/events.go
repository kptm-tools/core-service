package events

import (
	"github.com/kptm-tools/common/common/enums"
	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/events/consumers"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"slices"
)

func SetupEventBus(eventBus cmmn.EventBus, scanService interfaces.IScanService) error {
	// Initialize individual consumers

	whoIsEventHandler := consumers.NewWhoIsHandler(scanService)
	dnsLookupHandler := consumers.NewDNSLookupHandler(scanService)
	harvesterHandler := consumers.NewHarvesterHandler(scanService)

	nmapHandler := consumers.NewNmapHandler(scanService)

	err := eventBus.Subscribe(string(enums.DNSLookupEventSubject), dnsLookupHandler.HandleMessage)
	if err != nil {
		return err
	}

	if err := eventBus.Subscribe(string(enums.WhoIsEventSubject), whoIsEventHandler.HandleMessage); err != nil {
		return err
	}

	if err := eventBus.Subscribe(string(enums.HarvesterEventSubject), harvesterHandler.HandleMessage); err != nil {
		return err
	}

	if err := eventBus.Subscribe(string(enums.NmapEventSubject), nmapHandler.HandleMessage); err != nil {
		return err
	}

	return nil
}

func CanInsertScanResult(currentStatus string) bool {
	statusNotToUpdateResult := []string{enums.StatusFailed.String(), enums.StatusCancelled.String()}
	if !slices.Contains(statusNotToUpdateResult, currentStatus) {
		return true
	}
	return false
}

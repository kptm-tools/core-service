package events

import (
	"github.com/kptm-tools/common/common/pkg/enums"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/events/consumers"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

func SetupEventBus(eventBus cmmn.EventBus, scanService interfaces.IScanService) error {
	// Initialize individual consumers

	whoIsEventHandler := consumers.NewWhoIsHandler(scanService)
	dnsLookupHandler := consumers.NewDNSLookupHandler(scanService)
	harvesterHandler := consumers.NewHarvesterHandler(scanService)

	nmapHandler := consumers.NewNmapHandler(scanService)

	scanFailedHandler := consumers.NewScanFailedHandler(scanService)

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

	if err := eventBus.Subscribe(string(enums.ScanFailedEventSubject), scanFailedHandler.HandleMessage); err != nil {
		return err
	}

	return nil
}

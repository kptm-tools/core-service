package events

import (
	"github.com/kptm-tools/common/common/pkg/enums"
	cmmn "github.com/kptm-tools/common/common/pkg/events"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/events/consumers"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"strconv"
)

func SetupEventBus(
	cfg *config.Config,
	eventBus cmmn.EventBus,
	scanService interfaces.IScanService,
	vulnService interfaces.IVulnerabilityService,
) error {
	// Initialize individual consumers
	workerSize, _ := strconv.Atoi(cfg.Workers.Size)
	whoIsEventHandler := consumers.NewWhoIsHandler(scanService, workerSize)
	dnsLookupHandler := consumers.NewDNSLookupHandler(scanService, workerSize)
	harvesterHandler := consumers.NewHarvesterHandler(scanService, workerSize)

	nmapHandler := consumers.NewNmapHandler(scanService, vulnService, workerSize)
	webScanHandler := consumers.NewWebScanHandler(scanService, vulnService, workerSize)

	scanFailedHandler := consumers.NewScanFailedHandler(scanService, workerSize)

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
	if err := eventBus.Subscribe(string(enums.WebScanEventSubject), webScanHandler.HandleMessage); err != nil {
		return err
	}

	if err := eventBus.Subscribe(string(enums.ScanFailedEventSubject), scanFailedHandler.HandleMessage); err != nil {
		return err
	}

	return nil
}

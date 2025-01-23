package events

import (
	"fmt"

	"github.com/kptm-tools/common/common/enums"
	cmmn "github.com/kptm-tools/common/common/events"
	"github.com/kptm-tools/core-service/pkg/events/consumers"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

func SetupEventBus(eventBus cmmn.EventBus, scanService interfaces.IScanService) error {
	// Initialize individual consumers

	dnsLookupHandler := consumers.NewDNSLookupHandler(scanService)

	err := eventBus.Subscribe(string(enums.DNSLookupEventSubject), dnsLookupHandler.HandleMessage)
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", string(enums.DNSLookupEventSubject), err)
	}

	return nil
}

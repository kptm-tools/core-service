package consumers

import (
	"log/slog"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/nats-io/nats.go"
)

type DNSLookupHandler struct {
	scanService interfaces.IScanService
}

func NewDNSLookupHandler(scanService interfaces.IScanService) *DNSLookupHandler {
	return &DNSLookupHandler{scanService: scanService}
}

func (h *DNSLookupHandler) HandleMessage(msg *nats.Msg) {
	slog.Info("Received DNSLookupEvent")

}

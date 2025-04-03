package interfaces

import (
	"github.com/kptm-tools/core-service/pkg/ws/report"
	"github.com/kptm-tools/core-service/pkg/ws/scan"
)

type IClient interface {
	ReadMessages()
	WriteMessages()
	PongHandler(msg string) error
	GetScanClient() *scan.HubClientScan
	GetReportClient() *report.HubClientReport
}

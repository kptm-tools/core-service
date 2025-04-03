package ws

type IClient interface {
	ReadMessages()
	WriteMessages()
	PongHandler(msg string) error
	GetScanClient() *HubClientScan
	GetReportClient() *HubClientReport
}

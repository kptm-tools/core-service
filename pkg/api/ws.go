package api

import (
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/ws"
	"log"
	"net/http"
)

type WSServer struct {
	listenAddr       string
	hubScanHandler   ws.IHub
	hubReportHandler ws.IHub
}

func NewWSServer(
	listenAddr string,
	hubScanHandler ws.IHub,
	hubReportHandler ws.IHub,
) *WSServer {

	return &WSServer{
		listenAddr:       listenAddr,
		hubScanHandler:   hubScanHandler,
		hubReportHandler: hubReportHandler,
	}
}

func (wss *WSServer) Init() http.Server {
	router := http.NewServeMux()
	router.HandleFunc("/ws/scan", wss.hubScanHandler.Serve)
	router.HandleFunc("/ws/report/{scanId}", wss.hubReportHandler.Serve)
	stack := middleware.CreateStack(
		middleware.Logging,
		middleware.CheckCORS,
	)
	log.Println("Websocket Server listening on port: ", wss.listenAddr)
	return http.Server{
		Addr: wss.listenAddr,

		Handler: stack(router),
	}
}

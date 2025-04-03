package api

import (
	"log"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type WSServer struct {
	listenAddr string
	scanHub    common.IHub
	reportHub  common.IHub
}

// TODO: Add report hub

func NewWSServer(
	listenAddr string,
	scanHub common.IHub,
	// reportHub common.IHub,
) *WSServer {
	return &WSServer{
		listenAddr: listenAddr,
		scanHub:    scanHub,
		// reportHub:  reportHub,
	}
}

func (wss *WSServer) Init() http.Server {
	router := http.NewServeMux()

	go wss.scanHub.Run()
	// TODO: wss.reportHub.Run()

	router.HandleFunc("/ws/scan", wss.scanHub.Serve)
	// router.HandleFunc("/ws/report/{scanId}", wss.reportHub.Serve)

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

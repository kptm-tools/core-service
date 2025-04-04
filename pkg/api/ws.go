package api

import (
	"log"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/ws/common"
)

type WSServer struct {
	listenAddr  string
	authHandler interfaces.IAuthHandlers
	scanHub     common.IHub
	reportHub   common.IHub
}

func NewWSServer(
	listenAddr string,
	authHandler interfaces.IAuthHandlers,
	scanHub common.IHub,
	reportHub common.IHub,
) *WSServer {
	return &WSServer{
		listenAddr:  listenAddr,
		authHandler: authHandler,
		scanHub:     scanHub,
		reportHub:   reportHub,
	}
}

func (wss *WSServer) Init() http.Server {
	router := http.NewServeMux()

	go wss.scanHub.Run()
	go wss.reportHub.Run()

	router.HandleFunc("/ws/scan", wss.authHandler.WithAuth(wss.scanHub.Serve, "getScans"))
	router.HandleFunc("/ws/report/{scanId}", wss.authHandler.WithAuth(wss.reportHub.Serve, "dynamicReport"))

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

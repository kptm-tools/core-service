package api

import (
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/ws"
	"log"
	"net/http"
)

type WSServer struct {
	listenAddr string
	hub        *ws.Hub
}

func NewWSServer(
	listenAddr string,
	hub *ws.Hub,
) *WSServer {
	return &WSServer{
		listenAddr: listenAddr,
		hub:        hub,
	}
}

func (wss *WSServer) Init() http.Server {
	router := http.NewServeMux()
	router.HandleFunc("/ws/scan", wss.hub.ServeScan)
	router.HandleFunc("/ws/report/{scanId}", wss.hub.ServeScan)
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

package api

import (
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"log"
	"net/http"
)

type WSServer struct {
	listenAddr string
	wsHandler  interfaces.IWsHandler
}

func NewWSServer(
	listenAddr string,
	wsHandler interfaces.IWsHandler,
) *WSServer {
	return &WSServer{
		listenAddr: listenAddr,
		wsHandler:  wsHandler,
	}
}

func (wss *WSServer) Init() http.Server {
	router := http.NewServeMux()
	router.HandleFunc("/ws", wss.wsHandler.Serve)
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

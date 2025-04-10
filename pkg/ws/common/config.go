package common

import (
	"time"

	"github.com/gorilla/websocket"
)

type Config struct {
	Upgrader     websocket.Upgrader
	PongWait     time.Duration
	PingInterval time.Duration
}

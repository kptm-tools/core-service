package ws

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

var (
	ErrEventNotSupported = errors.New("this event type is not supported")
)

var (
	/**
	websocketUpgrader is used to upgrade incomming HTTP requests into a persitent websocket connection
	*/
	WebsocketUpgrader = websocket.Upgrader{
		// Apply the Origin Checker
		CheckOrigin:     checkOrigin,
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

var (
	// pongWait is how long we will await a pong response from client
	PongWait = 10 * time.Second
	// pingInterval has to be less than pongWait, We cant multiply by 0.9 to get 90% of time
	// Because that can make decimals, so instead *9 / 10 to get 90%
	// The reason why it has to be less than PingRequency is becuase otherwise it will send a new Ping before getting response
	PingInterval = (PongWait * 9) / 10
)

// checkOrigin will check origin and return true if its allowed
func checkOrigin(r *http.Request) bool {
	return true
}

func GetTenantIDFromHeader(req *http.Request) (string, error) {
	tenantID := req.Header.Get("X-TenantId")

	if err := uuid.Validate(tenantID); err != nil {
		return "", fmt.Errorf("invalid UUID: `%s`", tenantID)
	}
	return tenantID, nil
}

func GetScanID(req *http.Request) (uuid.UUID, error) {
	reqUUID := req.PathValue("scanId")

	u, err := uuid.Parse(reqUUID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse uuid: %w", err)
	}
	return u, nil
}

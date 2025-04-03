package scan

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/ws"
	interfaces2 "github.com/kptm-tools/core-service/pkg/ws/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/report"
	"log"
	"log/slog"
	"strconv"
	"time"
)

type HubClientScanList map[*HubClientScan]bool

type HubClientScan struct {
	// the websocket connection
	connection *websocket.Conn
	// hub is the hub used to manage the client
	hub *HubScan
	// tenantID is used to know what room user is in
	tenantID string
}

var _ interfaces2.IClient = (*HubClientScan)(nil)

// NewHubScanClient is used to initialize a new Client with all required values initialized
func NewHubScanClient(conn *websocket.Conn, hubScan *HubScan, tenantID string) *HubClientScan {
	return &HubClientScan{
		connection: conn,
		hub:        hubScan,
		tenantID:   tenantID,
	}
}

func (c *HubClientScan) GetHub() *HubScan {
	return c.hub
}

// ReadMessages will start the client to read messages and handle them
// appropriatly.
// This is suppose to be ran as a goroutine
func (c *HubClientScan) ReadMessages() {
	defer func() {
		// Graceful Close the Connection once this
		// function is done
		var iclient interfaces2.IClient = c
		c.GetHub().RemoveClient(&iclient)
	}()
	// Set Max Size of Messages in Bytes
	c.connection.SetReadLimit(512)
	// Configure Wait time for Pong response, use Current time + pongWait
	// This has to be done here to set the first initial timer.
	if err := c.connection.SetReadDeadline(time.Now().Add(ws.PongWait)); err != nil {
		log.Println(err)
		return
	}
	// Configure how to handle Pong responses
	c.connection.SetPongHandler(c.PongHandler)

	// Loop Forever
	for {
		// ReadMessage is used to read the next message in queue
		// in the connection
		_, _, err := c.connection.ReadMessage()

		if err != nil {
			// If Connection is closed, we will Recieve an error here
			// We only want to log Strange errors, but simple Disconnection
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error reading message: %v", err)
			}
			break // Break the loop to close conn & Cleanup
		}
	}
}

// PongHandler is used to handle PongMessages for the Client
func (c *HubClientScan) PongHandler(pongMsg string) error {
	// Current time + Pong Wait time
	return c.connection.SetReadDeadline(time.Now().Add(ws.PongWait))
}

// WriteMessages is a process that listens for new messages to output to the Client
func (c *HubClientScan) WriteMessages() {
	// Create a ticker that triggers a ping at given interval
	ticker := time.NewTicker(ws.PingInterval)
	scanInterval, _ := strconv.Atoi(c.hub.cfg.Websocket.IntervalScanRefresh)
	scanIntervalDuration := time.Duration(scanInterval) * time.Second
	tickerScan := time.NewTicker(scanIntervalDuration)
	defer func() {
		ticker.Stop()
		// Graceful close if this triggers a closing
		var interfaceClient interfaces2.IClient = c
		c.hub.RemoveClient(&interfaceClient)
	}()

	for {
		select {
		case <-ticker.C:
			log.Println("ping")
			// Send the Ping
			if err := c.connection.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Println("writemsg: ", err)
				return // return to break this goroutine triggeing cleanup
			}
		case <-tickerScan.C:
			scans, errGetScans := c.hub.scanService.GetCurrentScans(c.tenantID)
			if errGetScans != nil {
				slog.Error("Not able to get scans", slog.Any("tenantID", c.tenantID), slog.Any("error", errGetScans))
			}
			data, err := json.Marshal(scans)
			if err != nil {
				log.Println(err)
				return // closes the connection, should we really
			}
			if err := c.connection.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println(err)
			}
		}

	}
}

func (c *HubClientScan) GetScanClient() *HubClientScan {
	return c
}

func (c *HubClientScan) GetReportClient() *report.HubClientReport {
	return nil
}

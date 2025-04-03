package report

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/ws"
	"github.com/kptm-tools/core-service/pkg/ws/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/scan"
	"log"
	"time"
)

type VulnerabilityTypeData struct {
	Name                string    `json:"name"`
	HighestCvss         float64   `json:"highest_cvss"`
	Count               int       `json:"count"`
	Percentage          float64   `json:"percentage"`
	AvailableCvssValues []float64 `json:"available_cvss_values"`
}

type HubClientReportList map[*HubClientReport]bool

type HubClientReport struct {
	// the websocket connection
	connection *websocket.Conn

	// hub is the hub used to manage the client
	hub *HubReport
	// egress is used to avoid concurrent writes on the WebSocket
	egress chan domain.Event
	// tenantID is used to know what room user is in
	tenantID string
	scanID   string
	data     []*VulnerabilityTypeData
}

var _ interfaces.IClient = (*HubClientReport)(nil)

// NewHubReportClient is used to initialize a new Client with all required values initialized
func NewHubReportClient(conn *websocket.Conn, hub *HubReport, tenantID string, scanID string, data []*VulnerabilityTypeData) *HubClientReport {
	return &HubClientReport{
		connection: conn,
		hub:        hub,
		egress:     make(chan domain.Event),
		tenantID:   tenantID,
		scanID:     scanID,
		data:       data,
	}
}

// ReadMessages will start the client to read messages and handle them
// appropriatly.
// This is suppose to be ran as a goroutine
func (c *HubClientReport) ReadMessages() {
	defer func() {
		// Graceful Close the Connection once this
		// function is done
		var interfaceClient interfaces.IClient = c
		c.hub.RemoveClient(&interfaceClient)
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
		_, payload, err := c.connection.ReadMessage()

		if err != nil {
			// If Connection is closed, we will Recieve an error here
			// We only want to log Strange errors, but simple Disconnection
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error reading message: %v", err)
			}
			break // Break the loop to close conn & Cleanup
		}
		// Marshal incoming data into a Event struct
		var request domain.Event
		if err := json.Unmarshal(payload, &request); err != nil {
			log.Printf("error marshalling message: %v", err)
			break // Breaking the connection here might be harsh xD
		}
		// Route the Event
		var interfaceClient interfaces.IClient = c
		if err := c.hub.RouteEvent(request, &interfaceClient); err != nil {
			log.Println("Error handeling Message: ", err)
		}
	}
}

// PongHandler is used to handle PongMessages for the Client
func (c *HubClientReport) PongHandler(pongMsg string) error {
	// Current time + Pong Wait time
	return c.connection.SetReadDeadline(time.Now().Add(ws.PongWait))
}

// WriteMessages is a process that listens for new messages to output to the Client
func (c *HubClientReport) WriteMessages() {
	// Create a ticker that triggers a ping at given interval
	ticker := time.NewTicker(ws.PingInterval)
	defer func() {
		ticker.Stop()
		// Graceful close if this triggers a closing
		var interfaceClient interfaces.IClient = c
		c.hub.RemoveClient(&interfaceClient)
	}()

	for {
		select {
		case message, ok := <-c.egress:
			// Ok will be false Incase the egress channel is closed
			if !ok {
				// hub has closed this connection channel, so communicate that to frontend
				if err := c.connection.WriteMessage(websocket.CloseMessage, nil); err != nil {
					// Log that the connection is closed and the reason
					log.Println("connection closed: ", err)
				}
				// Return to close the goroutine
				return
			}

			data, err := json.Marshal(message)
			if err != nil {
				log.Println(err)
				return // closes the connection, should we really
			}
			// Write a Regular text message to the connection
			if err := c.connection.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Println(err)
			}
			log.Println("sent message")
		case <-ticker.C:
			log.Println("ping")
			// Send the Ping
			if err := c.connection.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Println("writemsg: ", err)
				return // return to break this goroutine triggeing cleanup
			}
		}

	}
}

// CountClientsByScanID counts the number clients connected to scanID this will be the room
func (c *HubClientReport) CountClientsByScanID(scanID string) int {
	size := 0
	for client := range c.hub.clients {
		if client.scanID == scanID {
			size += 1
		}
	}
	return size
}

func (c *HubClientReport) GetReportClient() *HubClientReport {
	return c
}

func (c *HubClientReport) GetScanClient() *scan.HubClientScan {
	return nil
}

package scan

import (
	"github.com/gorilla/websocket"
	"github.com/kptm-tools/core-service/pkg/mocks"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReportHub_WebSocketConnection(t *testing.T) {
	mockScanService := &mocks.MockScanService{}
	mockAuthService := &mocks.MockAuthService{}
	config := &common.Config{}

	hub := NewScanHub(config, mockScanService, mockAuthService, 1)

	server := httptest.NewServer(http.HandlerFunc(hub.Serve))
	defer server.Close()
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/scan?otp=131&tenantId=79c9acd6-a590-4394-8f2c-fadb07b79113"
	slog.Info("before dialing ", slog.Any("url", url))
	requestHeader := http.Header{}
	requestHeader.Add("Authorization", "Bearer token")
	requestHeader.Add("Origin", "http://localhost:8000")
	client, _, err := websocket.DefaultDialer.Dial(url, nil)

	if err != nil {
		t.Fatalf("Fallo la conexion WebSocket: %v", err)
	}
	defer client.Close()

	waitClosed := make(chan error)
	go func() {
		_, response, err := client.ReadMessage()
		if err != nil {
			// ...
		}
		slog.Info("after dialing ", slog.Any("resp", response))

		waitClosed <- err
	}()

	timeout := time.After(3 * time.Second)

	for {
		select {
		case <-timeout:
			// we timed out, so close the conection and quit!
			client.Close()
			return

		case <-waitClosed:
			// success! nothing needed here
			return
		}
	}

}

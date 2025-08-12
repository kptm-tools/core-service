package report

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	wshandlers "github.com/kptm-tools/core-service/pkg/ws/report/handlers"
	"github.com/kptm-tools/core-service/pkg/ws/utils"
)

type ReportHub struct {
	cfg         *common.Config
	clients     map[string]interfaces.IClient
	register    chan interfaces.IClient
	unregister  chan interfaces.IClient
	handlers    map[string]interfaces.IReportHandler
	authService interfaces.IAuthService
	scanService interfaces.IScanService
	rooms       *sync.Map
}

var _ interfaces.IHubReport = (*ReportHub)(nil)

// NewReportHub creates a ReportHub. If we use a particular service which we wish
// to inject to our services, we would ask for it as a parameter in NewReportHub()
// and pass it during handler initialization. This decision was made to avoid
// making main.go too bloated with code.
func NewReportHub(
	config *common.Config,
	scanService interfaces.IScanService,
	authService interfaces.IAuthService,
) *ReportHub {
	handlers := map[string]interfaces.IReportHandler{
		dto.MessageInitialRequest.String(): wshandlers.NewInitialRequestHandler(scanService),
		dto.MessageVectorUpdate.String():   wshandlers.NewVectorUpdateHandler(),
		dto.MessageSelectVector.String():   wshandlers.NewSelectVectorHandler(),
		dto.MessageApplyVectors.String():   wshandlers.NewApplyVectorsHandler(),
	}

	return &ReportHub{
		cfg:         config,
		clients:     make(map[string]interfaces.IClient),
		register:    make(chan interfaces.IClient),
		unregister:  make(chan interfaces.IClient),
		handlers:    handlers,
		authService: authService,
		scanService: scanService,
		rooms:       &sync.Map{},
	}
}

func (h *ReportHub) Serve(w http.ResponseWriter, r *http.Request) {
	otp, err := utils.GetOTPFromQuery(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	slog.Debug("REPORTS: Got OTP from header successfully", slog.String("otp", otp))

	if !h.authService.VerifyOTP(otp) {
		slog.Warn("Client OTP has expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	slog.Debug("REPORTS: Verified OTP successfully")

	conn, err := h.cfg.Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	// Create a new client
	client := NewReportClient(h.cfg, conn, h)

	// Register the new client to the hub
	h.Register(client)

	go client.WriteMessages()
	go client.ReadMessages()
}

// Run spins up the select statement for managing clients concurrently.
func (h *ReportHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client.GetID()] = client
		case client := <-h.unregister:
			if client, ok := h.clients[client.GetID()]; ok {
				slog.Info("Client unregistered", slog.String("client_id", client.GetID()))
				if err := client.Close(); err != nil {
					slog.Error("Failed to close client",
						slog.String("client_id", client.GetID()),
						slog.Any("error", err))
				}
				delete(h.clients, client.GetID())
			}
		}
	}
}

// Register will add clients to our clientList
func (h *ReportHub) Register(client interfaces.IClient) {
	// Add Client
	h.register <- client
}

// Unregister will remove clients from the clientList
func (h *ReportHub) Unregister(client interfaces.IClient) {
	h.unregister <- client
}

func (h *ReportHub) routeMessage(msg common.Message, client interfaces.IReportClient) error {
	handler, ok := h.handlers[msg.Type]
	if !ok {
		return customerrors.NewMessageNotSupportedError(msg.Type)
	}

	if err := handler.Handle(msg, client); err != nil {
		return err
	}

	return nil
}

func (h *ReportHub) AddToRoom(scanID string) {
	ctx := context.Background()
	scanUUID, err := uuid.Parse(scanID)
	if err != nil {
		slog.Error("Failed to parse scanID when adding client to room", slog.String("scan_id", scanID), slog.Any("error", err))
		return
	}
	roomInterface, _ := h.rooms.LoadOrStore(scanID, NewReportRoom(scanID))
	room, ok := roomInterface.(*ReportRoom)
	if !ok {
		slog.Error("Hub's room is not of type ReportRoom", slog.String("scan_id", scanID))
		return
	}
	room.mu.Lock()
	defer room.mu.Unlock()

	if room.AmountOfClients == 0 {
		slog.Debug("Fetching vulnerabilities for new room...")
		vulns, err := h.scanService.GetScanVulnerabilities(ctx, scanUUID)
		if err != nil {
			slog.Error("Failed to fetch vulnerabilities from DB when adding client to room", slog.Any("error", err))
			return
		}

		// Vulnerabilities now have their Type field properly populated from database OWASP categories
		// No need for runtime enhancement - the repository layer handles this
		room.Vulnerabilities = vulns
		room.AmountOfClients = 1
		slog.Info("Vulnerabilities loaded for scanID with database-driven OWASP categories", slog.String("scan_id", scanID))
	} else {
		room.AmountOfClients += 1
		slog.Info("Increasing the amount of clients for scanID", slog.String("scan_id", scanID))
	}
	slog.Info("Client joined room", slog.String("scan_id", scanID))
}

func (h *ReportHub) RemoveFromRoom(scanID string) {
	if scanID == "" {
		slog.Debug("RemoveFromRoom called with empty scanID, skipping")
		return
	}

	roomInterface, exists := h.rooms.Load(scanID)
	if !exists {
		slog.Debug("Room not found for scanID", slog.String("scanID", scanID))
		return
	}

	room, ok := roomInterface.(*ReportRoom)
	if !ok {
		slog.Error("Hub's room is not of type ReportRoom", slog.String("scanID", scanID))
		return
	}

	room.mu.Lock()
	defer room.mu.Unlock()
	slog.Info("Clients connected before remove", slog.Int("amount", room.AmountOfClients))
	slog.Info("Removing client from room", slog.String("scanID", scanID))
	room.AmountOfClients = room.AmountOfClients - 1
	h.rooms.Store(scanID, room)
	if room.AmountOfClients == 0 {
		slog.Info("Send to channel that should delete scanID", slog.String("scanID", scanID))
		ExecuteAfterDelay(5*time.Second, scanID, h)
	}
}

func ExecuteAfterDelay(delay time.Duration, scanID string, h *ReportHub) {
	time.AfterFunc(delay, func() {
		slog.Info("Entering to delete scanID", slog.String("scanID", scanID))
		roomInterface, _ := h.rooms.Load(scanID)
		room, ok := roomInterface.(*ReportRoom)
		if ok {
			if room.AmountOfClients == 0 {
				room.mu.Lock()
				defer room.mu.Unlock()
				slog.Info("Removing scanID from room", slog.String("scanID", scanID))
				h.rooms.Delete(scanID)
			}
		}
	})
}

func (h *ReportHub) GetRoomVulnerabilities(scanID string) []tools.Vulnerability {
	roomInterface, _ := h.rooms.Load(scanID)
	room, ok := roomInterface.(*ReportRoom)
	if ok {
		return room.Vulnerabilities
	}
	slog.Warn("No room value present for scanID", slog.String("scan_id", scanID))
	return nil
}

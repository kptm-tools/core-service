package report

import (
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/domain"
	"hash/fnv"
	"log/slog"
	"net/http"
	"time"

	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/ws/common"
	wshandlers "github.com/kptm-tools/core-service/pkg/ws/report/handlers"
	"github.com/kptm-tools/core-service/pkg/ws/utils"
	csmap "github.com/mhmtszr/concurrent-swiss-map"
)

type ReportHub struct {
	cfg            *common.Config
	clients        map[string]interfaces.IClient
	register       chan interfaces.IClient
	unregister     chan interfaces.IClient
	handlers       map[string]interfaces.IReportHandler
	authService    interfaces.IAuthService
	scanService    interfaces.IScanService
	rooms          *csmap.CsMap[string, Room]
	disconnectRoom chan string
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
		wshandlers.MessageInitialRequest: wshandlers.NewInitialRequestHandler(scanService),
		wshandlers.MessageVectorUpdate:   wshandlers.NewVectorUpdateHandler(),
		wshandlers.MessageSelectVector:   wshandlers.NewSelectVectorHandler(),
		wshandlers.MessageApplyVectors:   wshandlers.NewApplyVectorsHandler(),
	}
	roomsMap := csmap.Create[string, Room](
		// set the number of map shards. the default value is 32.
		csmap.WithShardCount[string, Room](32),

		// if don't set custom hasher, use the built-in maphash.
		csmap.WithCustomHasher[string, Room](func(key string) uint64 {
			hash := fnv.New64a()
			hash.Write([]byte(key))
			return hash.Sum64()
		}),

		// set the total capacity, every shard map has total capacity/shard count capacity. the default value is 0.
		csmap.WithSize[string, Room](1000),
	)
	return &ReportHub{
		cfg:         config,
		clients:     make(map[string]interfaces.IClient),
		register:    make(chan interfaces.IClient),
		unregister:  make(chan interfaces.IClient),
		handlers:    handlers,
		authService: authService,
		scanService: scanService,
		rooms:       roomsMap,
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
	room, ok := h.rooms.Load(scanID)
	if ok {
		room.AmountOfClients = room.AmountOfClients + 1
		h.rooms.Store(scanID, room)
	} else {
		scanIDUUID, errParsing := uuid.Parse(scanID)
		if errParsing != nil {
			slog.Error("Failed to parse scan ID", slog.String("scanID", scanID))
		}
		data, errGet := h.scanService.GetScanVulnerabilities(scanIDUUID)
		if errGet != nil {
			slog.Error("Failed to get scan vulnerabilities", slog.String("scanID", scanID))
		}
		roomScan := Room{
			Vulnerabilities: data,
			AmountOfClients: 1,
		}
		h.rooms.Store(scanID, roomScan)
	}

}

func (h *ReportHub) RemoveFromRoom(scanID string) {
	room, ok := h.rooms.Load(scanID)
	slog.Info("Clients connected before remove", slog.Int("amount", room.AmountOfClients))
	if ok {
		slog.Info("Removing client from room", slog.String("scanID", scanID))
		room.AmountOfClients = room.AmountOfClients - 1
		h.rooms.Store(scanID, room)
		if room.AmountOfClients == 0 {
			slog.Info("Send to channel that should delete scanID", slog.String("scanID", scanID))
			ExecuteAfterDelay(5*time.Second, scanID, h)
		}
	}
}

func ExecuteAfterDelay(delay time.Duration, scanID string, h *ReportHub) {
	time.AfterFunc(delay, func() {
		slog.Info("Entering to delete scanID", slog.String("scanID", scanID))
		room, ok := h.rooms.Load(scanID)
		if ok {
			if room.AmountOfClients == 0 {
				slog.Info("Removing scanID from room", slog.String("scanID", scanID))
				h.rooms.Delete(scanID)
			}
		}
	})
}

func (h *ReportHub) GetRoomVulnerabilities(scanID string) []*domain.Vulnerability {
	val, ok := h.rooms.Load(scanID)
	if ok {
		return val.Vulnerabilities
	}
	slog.Warn("No room value present for scanID", slog.String("scan_id", scanID))
	return nil
}

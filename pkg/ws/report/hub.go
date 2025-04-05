package report

import (
	"log/slog"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/customerrors"
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
}

var _ interfaces.IHub = (*ReportHub)(nil)

// NewReportHub creates a ReportHub. If we use a particular service which we wish
// to inject to our services, we would ask for it as a parameter in NewReportHub()
// and pass it during handler initialization. This decision was made to avoid
// making main.go too bloated with code.
func NewReportHub(
	config *common.Config,
	scanService interfaces.IScanService,
) *ReportHub {
	handlers := map[string]interfaces.IReportHandler{
		wshandlers.MessageInitialRequest: wshandlers.NewInitialRequestHandler(scanService),
		wshandlers.MessageVectorUpdate:   wshandlers.NewVectorUpdateHandler(),
		wshandlers.MessageSelectVector:   wshandlers.NewSelectVectorHandler(),
		wshandlers.MessageApplyVectors:   wshandlers.NewApplyVectorsHandler(),
	}

	return &ReportHub{
		cfg:        config,
		clients:    make(map[string]interfaces.IClient),
		register:   make(chan interfaces.IClient),
		unregister: make(chan interfaces.IClient),
		handlers:   handlers,
	}
}

func (h *ReportHub) Serve(w http.ResponseWriter, r *http.Request) {
	otp, err := utils.GetOTPFromQuery(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if !h.authService.VerifyOTP(otp) {
		slog.Warn("Client OTP has expired")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

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
		return customerrors.ErrMessageNotSupported
	}

	if err := handler.Handle(msg, client); err != nil {
		return err
	}

	return nil
}

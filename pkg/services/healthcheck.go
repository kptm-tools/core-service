package services

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type HealthCheckService struct {
	storage    interfaces.IStorage
	httpClient http.Client
	config     *config.Config
}

var _ interfaces.IHealthcheckService = (*HealthCheckService)(nil)

func NewHealthcheckService(cfg *config.Config, storage interfaces.IStorage) *HealthCheckService {
	client := http.Client{
		Timeout: time.Second * 5,
	}
	return &HealthCheckService{
		storage:    storage,
		httpClient: client,
		config:     cfg,
	}
}

func (s *HealthCheckService) CheckHealth() *interfaces.HealthStatus {
	status := &interfaces.HealthStatus{OverallHealthy: true}

	dbErr := s.storage.Ping()
	if dbErr != nil {
		status.DatabaseHealthy = false
		status.DatabaseError = fmt.Sprintf("%q: %v", dbErr.Error(), customerrors.ErrorDBUnhealthy)
		status.OverallHealthy = false
		slog.Error("Database health check failed", slog.Any("db_err", dbErr))
	} else {
		status.DatabaseHealthy = true
	}

	ebErr := s.checkEventBusHealth()
	if ebErr != nil {
		status.EventBusHealthy = false
		status.EventBusError = ebErr.Error()
		status.OverallHealthy = false
		slog.Error("Event bus health check failed", slog.Any("eb_err", ebErr))
	} else {
		status.EventBusHealthy = true
	}

	return status
}

func (s *HealthCheckService) checkEventBusHealth() error {
	resp, err := s.httpClient.Get(s.config.GetNatsHealthcheckURL())
	if err != nil {
		return fmt.Errorf("failed to perform event bus health check request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("%w: received status code %d", customerrors.ErrEventBusUnhealthy, resp.StatusCode)
	}
	return nil
}

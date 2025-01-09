package services

import (
	"errors"
	"fmt"

	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type HealthCheckService struct {
	storage interfaces.IStorage
}

var _ interfaces.IHealthcheckService = (*HealthCheckService)(nil)

func NewHealthcheckService(storage interfaces.IStorage) *HealthCheckService {
	return &HealthCheckService{
		storage: storage,
	}
}

var ErrorUnhealthy = errors.New("DB is unhealthy")

func (s *HealthCheckService) CheckHealth() error {

	if err := s.storage.Ping(); err != nil {
		return fmt.Errorf("%q: %w", err.Error(), ErrorUnhealthy)
	}

	return nil

}

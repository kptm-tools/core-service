package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/utils/validation"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	probing "github.com/prometheus-community/pro-bing"
)

var (
	ErrInvalidHostValue = errors.New("invalid host")
	ErrHostUnhealthy    = errors.New("unable to connect to host")
	ErrAliasTaken       = errors.New("alias is taken")
)

type HostService struct {
	hostRepo interfaces.HostRepository
}

var _ interfaces.IHostService = (*HostService)(nil)

func NewHostService(hostRepository interfaces.HostRepository) *HostService {
	return &HostService{
		hostRepo: hostRepository,
	}
}

func (s *HostService) CreateHost(ctx context.Context, t *domain.Host) (*domain.Host, error) {
	return s.hostRepo.CreateHost(ctx, t)
}

func (s *HostService) GetHostsByTenantID(ctx context.Context, tenantID uuid.UUID) ([]*domain.Host, error) {
	return s.hostRepo.GetHostsByTenantID(ctx, tenantID, []uuid.UUID{})
}

func (s *HostService) GetHostByID(ctx context.Context, hostID uuid.UUID) (*domain.Host, error) {
	return s.hostRepo.GetHostByID(ctx, hostID)
}

func (s *HostService) DeleteHostByID(ctx context.Context, hostID uuid.UUID) (bool, error) {
	isDeleted, err := s.hostRepo.DeleteHostByID(ctx, hostID)
	if err != nil {
		return false, err
	}

	return isDeleted, nil
}

func (s *HostService) PatchHostByID(ctx context.Context, h *domain.Host) (*domain.Host, error) {
	host, err := s.hostRepo.PatchHostByID(ctx, *h)
	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) ValidateHost(ctx context.Context, host string) error {
	classification, err := validation.ClassifyHostValue(host)
	if err != nil {
		slog.Error("Failed to classify host", slog.Any("error", err))
		return ErrInvalidHostValue
	}

	normalizedHost := classification.NormalizedValue
	addr := strings.Split(normalizedHost, "//")[1]
	pinger, err := probing.NewPinger(addr)
	if err != nil {
		slog.Error("Failed to probe host", slog.Any("error", err))
		return ErrHostUnhealthy
	}
	pinger.Count = 1
	pinger.Timeout = 5 * time.Second
	err = pinger.Run()
	defer pinger.Stop()
	if err != nil {
		return err
	}
	stats := pinger.Statistics()
	if stats.PacketLoss == 100 {
		slog.Error("Failed to ping host", slog.String("address", stats.IPAddr.String()))
		return ErrHostUnhealthy
	}
	slog.Debug("Pinger stats", slog.Any("stats", pinger.Statistics()))
	return nil
}

func (s *HostService) ValidateAlias(ctx context.Context, alias string) error {
	exists, err := s.hostRepo.AliasExists(ctx, alias)
	if err != nil {
		return err
	}
	if exists {
		return ErrAliasTaken
	}
	return nil
}

func (s *HostService) GetDomainIPValues(value string) (*domain.DomainIPResult, error) {
	classification, err := validation.ClassifyHostValue(value)
	if err != nil {
		return nil, fmt.Errorf("failed to classify host value: %w", err)
	}

	switch classification.Type {
	case enums.Domain, enums.Subdomain:

		url := classification.NormalizedValue
		return s.handleDomainType(url)
	case enums.IP:
		url := classification.NormalizedValue
		return s.handleIPType(url)

	default:
		return nil, fmt.Errorf("invalid host type: %s", classification.Type.String())
	}
}

// handleDomainType handles domain and subdomain cases
func (s *HostService) handleDomainType(normalizedURL string) (*domain.DomainIPResult, error) {
	if !validation.IsURL(normalizedURL) {
		return nil, fmt.Errorf("invalid url: %s", normalizedURL)
	}

	hostName, err := validation.ExtractHostName(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("failed to extract domain: %w", err)
	}

	// Attempt to DNS lookup IP
	ip, err := s.findFirstIPv4(hostName)
	if err != nil {
		return nil, fmt.Errorf("failed to find first IPv4: %w", err)
	}
	return &domain.DomainIPResult{
		Domain: hostName,
		IP:     ip,
	}, nil
}

func (s *HostService) findFirstIPv4(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("error looking up IP of domain: %w", err)
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for hostname: %s", domain)
}

// handleIPType handles IP cases
func (s *HostService) handleIPType(normalizedURL string) (*domain.DomainIPResult, error) {
	ipValue := strings.Split(normalizedURL, "//")[1]

	return &domain.DomainIPResult{
		Domain: "",
		IP:     ipValue,
	}, nil
}

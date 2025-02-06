package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

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
	storage interfaces.IStorage
}

var _ interfaces.IHostService = (*HostService)(nil)

func NewHostService(storage interfaces.IStorage) *HostService {
	return &HostService{
		storage: storage,
	}
}

func (s *HostService) CreateHost(t *domain.Host) (*domain.Host, error) {

	return s.storage.CreateHost(t)
}

func (s *HostService) GetHostsByTenantIDAndUserID(tenantID string, userID string) ([]*domain.Host, error) {

	hosts, err := s.storage.GetHostsByTenantIDAndUserID(tenantID, userID)

	if err != nil {
		return nil, err
	}

	return hosts, nil
}

func (s *HostService) GetHostByID(ID int) (*domain.Host, error) {
	host, err := s.storage.GetHostByID(ID)

	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) DeleteHostByID(ID int) (bool, error) {
	isDeleted, err := s.storage.DeleteHostByID(ID)

	if err != nil {
		return false, err
	}

	return isDeleted, nil
}

func (s *HostService) PatchHostByID(h *domain.Host) (*domain.Host, error) {
	host, err := s.storage.PatchHostByID(h)

	if err != nil {
		return nil, err
	}

	return host, nil
}

func (s *HostService) GetHostNameFromIP(ip string) ([]string, error) {
	return s.GetHostNameFromIPWithTimeout(ip, 10*time.Second)
}

func (s *HostService) GetHostNameFromIPWithTimeout(ip string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	results := make(chan []string, 1)
	errors := make(chan error, 1)

	go func() {
		if net.ParseIP(ip) == nil {
			errors <- fmt.Errorf("invalid IP address format: %s", ip)
			return
		}

		hostnames, err := net.DefaultResolver.LookupAddr(ctx, ip)
		if err != nil {
			errors <- fmt.Errorf("reverse DNS lookup failed: %w", err)
			return
		}

		// Clean up hostnames (remove trailing dots)
		cleaned := make([]string, len(hostnames))
		for i, hostname := range hostnames {
			cleaned[i] = strings.TrimSuffix(hostname, ".")
		}

		results <- cleaned
	}()

	// Wait for either results or timeout
	select {
	case hostnames := <-results:
		return hostnames, nil
	case err := <-errors:
		return nil, err
	case <-ctx.Done():
		return nil, fmt.Errorf("lookup timed out after %v", timeout)
	}
}

func (s *HostService) ValidateHost(host string) error {

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

	slog.Debug("Pinger stats", slog.Any("stats", pinger.Statistics()))
	return nil
}

func (s *HostService) ValidateAlias(alias string) error {
	exists, err := s.storage.ExistAlias(alias)
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
		return nil, fmt.Errorf("invalid host type: must be one of `%s` or `%s`", string(enums.Domain), string(enums.IP))
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

	hostNames, err := s.GetHostNameFromIP(ipValue)
	if err != nil {
		return nil, fmt.Errorf("failed to get hostnames form IP: %w", err)
	}

	hostName := ""
	if len(hostNames) > 0 {
		hostName = hostNames[0]
	}

	return &domain.DomainIPResult{
		Domain: hostName,
		IP:     ipValue,
	}, nil
}

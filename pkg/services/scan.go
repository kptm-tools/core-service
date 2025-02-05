package services

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/results"

	"github.com/kptm-tools/common/common/enums"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type ScanService struct {
	storage interfaces.IStorage
}

var _ interfaces.IScanService = (*ScanService)(nil)

func NewScanService(storage interfaces.IStorage) *ScanService {
	return &ScanService{
		storage: storage,
	}
}

func (s ScanService) CreateScans(hostIDs []int, tenantID, operatorID string) ([]*domain.Scan, error) {
	scanDB := domain.NewScan()
	scanDB.TenantID = tenantID
	scanDB.OperatorID = operatorID

	dataScans, err := s.storage.CreateScans(scanDB, hostIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}
	for _, dataScan := range dataScans {
		host, err := s.storage.GetHostByID(dataScan.HostID)
		if err != nil {
			return nil, fmt.Errorf("failed to get host: %w", err)
		}

		dataScan.Target = createTarget(*host)
	}
	return dataScans, nil
}

func createTarget(host domain.Host) results.Target {
	var hostValue string
	var hostType enums.TargetType
	if host.Domain == "" {
		hostType = enums.IP
		hostValue = host.IP
	} else {
		hostType = enums.Domain
		hostValue = host.Domain
	}

	target := results.Target{
		Alias: host.Name,
		Value: hostValue,
		Type:  hostType,
	}
	return target
}

func (s ScanService) GetScans(tenantID string) ([]*domain.ScanSummary, error) {
	return s.storage.GetScans(tenantID)
}

func (s *ScanService) InsertScanResult(scanResult *domain.ScanResult) error {
	return s.storage.InsertScanResult(nil, scanResult)
}

func (s *ScanService) InsertVulnerabilityResult(scanResult *domain.ScanResult) error {
	return s.storage.InsertVulnerabilityResult(scanResult)
}

func (s *ScanService) UpdateScanStatus(scanID uuid.UUID, status enums.ScanStatus) error {
	return s.storage.UpdateScanStatus(scanID, status.String())
}

func (s *ScanService) MarkScanAsFailed(scanID uuid.UUID) error {
	scan, err := s.storage.GetScanByID(scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan by ID: %w", err)
	}

	if scan.IsFinished() {
		return customerrors.NewScanAlreadyFinishedError(scanID, scan.Status)
	}

	err = s.storage.UpdateScanStatusAndEndedAt(nil, scanID, enums.StatusFailed.String(), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update scan status and ended_at: %w", err)
	}
	return nil
}

func (s *ScanService) MarkScanAsCancelled(scanID uuid.UUID) error {

	scan, err := s.storage.GetScanByID(scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan by ID: %w", err)
	}

	if scan.IsFinished() {
		return customerrors.NewScanAlreadyFinishedError(scanID, scan.Status)
	}

	err = s.storage.UpdateScanStatusAndEndedAt(nil, scanID, enums.StatusCancelled.String(), time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update scan status and ended_at: %w", err)
	}
	return nil
}

func (s *ScanService) GetScanInsightsByID(scanID uuid.UUID) (*domain.ScanInsights, error) {
	return s.storage.GetScanInsights(scanID)
}

func (s *ScanService) CalculateProtectionScore(scanID uuid.UUID) (float64, error) {
	return s.storage.GetProtectionScore(scanID)
}

func (s *ScanService) GetScanByID(scanID uuid.UUID) (*domain.Scan, error) {
	scan, err := s.storage.GetScanByID(scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain scan by ID : %w", err)
	}
	return scan, nil
}

func (s *ScanService) HandleScanCompletion(scanID uuid.UUID) error {
	slog.Info("Scan Service handling scan completion...")

	whoIsResult, err := s.storage.GetWhoisResult(scanID)
	if err != nil {
		return fmt.Errorf("failed to get WhoisResult: %w", err)
	}

	dnsLookupResult, err := s.storage.GetDNSLookupResult(scanID)
	if err != nil {
		return fmt.Errorf("failed to fetch DNSLookupResult: %w", err)
	}

	harvesterResult, err := s.storage.GetHarvesterResult(scanID)
	if err != nil {
		return fmt.Errorf("failed to fetch HarvesterResult: %w", err)
	}

	nmapResult, err := s.storage.GetNmapResult(scanID)
	if err != nil {
		return fmt.Errorf("failed to fetch NmapResult: %w", err)
	}

	protectionScore, err := results.CalculateProtectionScore(
		*whoIsResult,
		*dnsLookupResult,
		*harvesterResult,
		*nmapResult,
	)
	if err != nil {
		return fmt.Errorf("failed to calculate protection score: %w", err)
	}

	// Update protection score
	if err := s.storage.UpdateProtectionScore(scanID, protectionScore); err != nil {
		return fmt.Errorf("failed to update protection score on scan: %w", err)
	}

	return nil
}

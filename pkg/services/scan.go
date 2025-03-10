package services

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/common/common/pkg/utils/validation"

	"github.com/kptm-tools/common/common/pkg/enums"
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

func (s ScanService) CreateScan(hostID int, tenantID, operatorID string, startedAt *time.Time) (*domain.Scan, error) {
	var startScanDate time.Time
	if startedAt == nil {
		startScanDate = time.Now().UTC()
	} else {
		startScanDate = *startedAt
	}
	commonScanData := domain.NewScan(startScanDate)
	commonScanData.TenantID = tenantID
	commonScanData.OperatorID = operatorID

	// 1. Create the scan in storage
	scanToCreate := *commonScanData
	scanToCreate.HostID = hostID
	dataScan, err := s.storage.CreateScan(&scanToCreate)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	// 3. Add the target to the scan
	target, err := s.CreateTarget(scanToCreate.HostID)
	if err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}

	dataScan.Target = *target

	return dataScan, nil
}

func (s ScanService) CreateTarget(hostID int) (*results.Target, error) {
	// 1. Get host details
	host, err := s.storage.GetHostByID(hostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get host: %w", err)
	}
	// 2. Construct the target
	var hostValue string
	var hostType enums.TargetType
	if host.Domain == "" {
		hostType = enums.IP
		hostValue = host.IP
	} else {
		classification, err := validation.ClassifyHostValue(host.Domain)
		if err != nil {
			return nil, fmt.Errorf("failed to classify host value: %w", err)
		}
		hostType = classification.Type
		hostValue = host.Domain
	}

	return &results.Target{
		Alias: host.Name,
		Value: hostValue,
		Type:  hostType,
	}, nil
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

func (s *ScanService) GetScanVulnerabilitySummaryByID(
	scanID uuid.UUID,
	timePeriodFilter domain.TimePeriodFilter,
	severityFilters []string,
) (*domain.ScanVulnerabilitySummaryData, error) {
	slog.Debug("Fetching scan vulnerabilities summary...", slog.String("scan_id", scanID.String()))

	summaryData, err := s.storage.GetScanVulnerabilitiesSummary(scanID, timePeriodFilter, severityFilters)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerabilities summary: %w", err)
	}

	return summaryData, nil
}

func (s *ScanService) GetAllReportsForTenant(tenantID string) ([]*domain.ReportItem, error) {
	reportItems, err := s.storage.GetReportsByTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch reports from storage: %w", err)
	}

	// If err is nil and reportItems is nil, it means sql.ErrNoRows was handled in storage
	if reportItems == nil {
		return []*domain.ReportItem{}, nil
	}

	return reportItems, nil
}

func (s *ScanService) GetScoreCardTrendsForTenant(tenantID string, fromDate, toDate *time.Time) ([]*domain.ScoreCardTrendItem, error) {
	hosts, err := s.storage.GetHostsByTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts for tenant %s: %w", tenantID, err)
	}

	slog.Debug("Got hosts", slog.Any("hosts", hosts))

	scoreCardItems := make([]*domain.ScoreCardTrendItem, 0, len(hosts))
	for _, host := range hosts {
		oldestScan, latestScan, err := s.getOldestLatestScans(host.ID, fromDate, toDate)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch oldest and latest scan: %w", err)
		}

		var oldestProtectionScore, latestProtectionScore *float64
		if oldestScan != nil {
			oldestProtectionScore = oldestScan.ProtectionScore
		}
		if latestScan != nil {
			latestProtectionScore = latestScan.ProtectionScore
		}

		scoreCardItem := domain.NewScoreCardTrendItem(host.Name, oldestProtectionScore, latestProtectionScore)

		scoreCardItems = append(scoreCardItems, scoreCardItem)
	}

	return scoreCardItems, nil
}

func (s *ScanService) getOldestLatestScans(hostID int, fromDate, toDate *time.Time) (*domain.Scan, *domain.Scan, error) {
	oldestScan, err := s.storage.GetOldestScanByHostID(hostID, fromDate, toDate)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("failed to get oldest scan: %w", err)
		}
	}
	latestScan, err := s.storage.GetLatestScanByHostID(hostID, fromDate, toDate)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("failed to get latest scan: %w", err)
		}
	}

	slog.Debug("Got oldest and latest scan",
		slog.Any("oldest_scan", oldestScan),
		slog.Any("latest_scan", latestScan),
	)

	// If the oldest scan and latest scan are the same, only return the latest scan
	if oldestScan != nil && latestScan != nil {
		if oldestScan.ID == latestScan.ID {
			return nil, latestScan, nil
		}
	}

	return oldestScan, latestScan, nil
}

func (s *ScanService) GetScanVulnerabilities(scanID uuid.UUID) ([]*domain.Vulnerability, error) {
	return s.storage.GetScanVulnerabilities(scanID)
}

func (s *ScanService) GetSeverityCounts(scanID uuid.UUID) (*tools.SeverityCounts, error) {
	return s.storage.GetSeverityCounts(scanID)
}

func (s ScanService) UpdateScanScheduleScanID(scanID uuid.UUID, scanScheduleID int) error {
	return s.storage.UpdateScanScheduling(scanID, scanScheduleID)
}

func (s ScanService) ScanScheduleDisableJob(scanScheduleID int) error {
	return s.storage.ScanScheduleDisableJob(scanScheduleID, false)
}

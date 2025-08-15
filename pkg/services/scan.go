package services

import (
	"context"
	"database/sql"
	"encoding/json"
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
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type ScanService struct {
	vulnRepo        interfaces.VulnerabilityRepository
	scanRepo        interfaces.ScanRepository
	hostRepo        interfaces.HostRepository
	scanResultsRepo interfaces.ScanResultRepository
}

var _ interfaces.IScanService = (*ScanService)(nil)

func NewScanService(
	vulnerabilityRepository interfaces.VulnerabilityRepository,
	scanRepository interfaces.ScanRepository,
	hostRepository interfaces.HostRepository,
	scanResultRepository interfaces.ScanResultRepository,
) *ScanService {
	return &ScanService{
		vulnRepo:        vulnerabilityRepository,
		scanRepo:        scanRepository,
		hostRepo:        hostRepository,
		scanResultsRepo: scanResultRepository,
	}
}

func (s ScanService) CreateScan(
	ctx context.Context,
	hostID, tenantID, operatorID uuid.UUID,
	startedAt *time.Time,
) (*domain.Scan, error) {
	commonScanData := domain.NewScan(hostID, tenantID, operatorID, startedAt)
	commonScanData.TenantID = tenantID
	commonScanData.OperatorID = operatorID
	if startedAt != nil {
		commonScanData.Status = enums.StatusScheduled.String()
	}
	// 1. Create the scan in storage
	scanToCreate := *commonScanData
	scanToCreate.HostID = hostID
	dataScan, err := s.scanRepo.CreateScan(ctx, scanToCreate)
	if err != nil {
		return nil, err
	}

	// 3. Add the target to the scan
	target, err := s.CreateTarget(ctx, scanToCreate.HostID)
	if err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}

	dataScan.Target = *target

	return dataScan, nil
}

func (s ScanService) CreateTarget(ctx context.Context, hostID uuid.UUID) (*results.Target, error) {
	// 1. Get host details
	host, err := s.hostRepo.GetHostByID(ctx, hostID)
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

func (s ScanService) GetCurrentScans(ctx context.Context, tenantID uuid.UUID) ([]domain.ScanSummary, error) {
	scans, err := s.scanRepo.GetScansForTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current scans for tenant from db: %w", err)
	}
	return scans, nil
}

func (s *ScanService) InsertScanResult(ctx context.Context, result domain.ScanResult) error {
	return s.scanResultsRepo.CreateScanResult(ctx, result)
}

func (s *ScanService) UpdateScanStatus(ctx context.Context, scanID uuid.UUID, status enums.ScanStatus) error {
	return s.scanRepo.UpdateScanStatus(ctx, scanID, status)
}

func (s *ScanService) MarkScanAsFailed(ctx context.Context, scanID uuid.UUID) error {
	scan, err := s.scanRepo.GetScanByID(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan by ID: %w", err)
	}

	if scan.IsFinished() {
		return customerrors.NewScanAlreadyFinishedError(scanID, scan.Status)
	}

	err = s.scanRepo.UpdateScanStatusAndEndedAt(ctx, scanID, enums.StatusFailed, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update scan status and ended_at: %w", err)
	}
	return nil
}

func (s *ScanService) MarkScanAsCancelled(ctx context.Context, scanID uuid.UUID) error {
	scan, err := s.scanRepo.GetScanByID(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to get scan by ID: %w", err)
	}

	if scan.IsFinished() {
		return customerrors.NewScanAlreadyFinishedError(scanID, scan.Status)
	}

	err = s.scanRepo.UpdateScanStatusAndEndedAt(ctx, scanID, enums.StatusCancelled, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to update scan status and ended_at: %w", err)
	}
	return nil
}

func (s *ScanService) GetScanInsights(ctx context.Context, scanID uuid.UUID) (*domain.ScanInsights, error) {
	var insights domain.ScanInsights

	// 1. Get base data from the main query
	baseData, err := s.scanRepo.GetScanInsightsBaseData(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan base insights: %w", err)
	}

	insights.Metadata = domain.ScanInsightsMetadata{
		ScanID:    baseData.ScanID,
		HostAlias: baseData.HostAlias,
		ScanDate:  baseData.ScanDate,
	}
	insights.TotalVulnerabilities = baseData.TotalVulnerabilities
	insights.SeverityCounts = tools.SeverityCounts{
		Unknown:  baseData.UnknownVulnerabilities,
		None:     baseData.NoneVulnerabilities,
		Low:      baseData.LowVulnerabilities,
		Medium:   baseData.MediumVulnerabilities,
		High:     baseData.HighVulnerabilities,
		Critical: baseData.CriticalVulnerabilities,
	}

	// 2. Process SeverityPerType
	var rawSeverityPerType map[string]float64
	if err := json.Unmarshal(baseData.SeverityPerTypeJSON, &rawSeverityPerType); err != nil {
		return nil, fmt.Errorf("failed to unmarshal severity_per_type map: %w", err)
	}

	insights.SeverityPerType = make(map[string]string)
	for vulnType, cvssScore := range rawSeverityPerType {
		insights.SeverityPerType[vulnType] = tools.MapCVSS(cvssScore).String()
	}

	// 3. Get current scan's protection score
	currentProtectionScore, err := s.scanRepo.GetProtectionScore(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get protection score for current scan: %w", err)
	}
	insights.ProtectionScore = currentProtectionScore

	// 4. Handle variations by looking at the scan before this one.
	prevScan, err := s.scanRepo.GetPreviousScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get previousScan: %w", err)
	}
	// At this point, we're pretty sure the current scan already exists
	// so the previousScan query should only return nil if the previousScan is nil.
	insights.VulnerabilityVariation = 0
	insights.ProtectionScoreVariation = 0.0
	// Calculate variations
	if prevScan != nil && !prevScan.IsFailedOrCancelled() {
		// TotalVulnerabilities
		prevBaseData, err := s.scanRepo.GetScanInsightsBaseData(ctx, prevScan.ID)
		if err != nil {
			slog.Warn("Failed to get previous scan's base insight data", slog.Any("error", err))
		} else {
			insights.VulnerabilityVariation = insights.TotalVulnerabilities - prevBaseData.TotalVulnerabilities
		}

		// ProtectionScore
		prevProtectionScore, err := s.scanRepo.GetProtectionScore(ctx, prevScan.ID)
		if err != nil {
			slog.Warn("Failed to get previous scan's protection score", slog.Any("error", err))
		} else {
			insights.ProtectionScoreVariation = insights.ProtectionScore - prevProtectionScore
		}
	}
	// If the prevScan was nil, the variations remained as 0 values.

	return &insights, nil
}

func (s *ScanService) CalculateProtectionScore(ctx context.Context, scanID uuid.UUID) (float64, error) {
	return s.scanRepo.GetProtectionScore(ctx, scanID)
}

func (s *ScanService) GetScanByID(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
	scan, err := s.scanRepo.GetScanByID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain scan by ID : %w", err)
	}
	return scan, nil
}

func (s *ScanService) GetScanAssetsByID(ctx context.Context, scanID uuid.UUID) ([]domain.ScanOSandServicesResult, error) {
	return s.scanRepo.GetScanAssetsByID(ctx, scanID)
}

func (s *ScanService) HandleScanCompletion(ctx context.Context, scanID uuid.UUID) error {
	slog.Info("Scan Service handling scan completion...")

	// Protection score
	protectionScore, err := s.scanRepo.GetProtectionScore(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to calculate protection score: %w", err)
	}

	// Update protection score
	if err := s.scanRepo.UpdateProtectionScore(ctx, scanID, protectionScore); err != nil {
		return fmt.Errorf("failed to update protection score on scan: %w", err)
	}

	return nil
}

func (s *ScanService) GetScanVulnerabilitySummaryByID(
	ctx context.Context,
	scanID uuid.UUID,
	timePeriodFilter domain.TimePeriodFilter,
	severityFilters []string,
) (*domain.ScanVulnerabilitySummaryData, error) {
	slog.Debug("Fetching scan vulnerabilities summary...", slog.String("scan_id", scanID.String()))

	summaryData := domain.ScanVulnerabilitySummaryData{ScanID: scanID}

	// 1. Get Host Alias and Host ID from scan
	scan, err := s.scanRepo.GetScanByID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan by ID: %w", err)
	}
	target, err := s.CreateTarget(ctx, scan.HostID)
	if err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}
	if target != nil {
		scan.Target = *target
	}

	summaryData.Domain = scan.Target.Value

	// 2. Get Vulnerability Aggregates (Summary)
	aggParams := dto.VulnerabilityAggregatesParams{
		ScanID:          scanID,
		SeverityFilters: severityFilters,
	}
	vulnAggregates, err := s.vulnRepo.GetScanVulnerabilityAggregates(ctx, aggParams)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch vulnerability aggregates: %w", err)
	}
	summaryData.TotalVulnerabilities = vulnAggregates.TotalVulnerabilities
	summaryData.SeverityCounts = vulnAggregates.SeverityCounts

	// 3. Get Vulnerability Categories
	catParams := dto.VulnerabilityCategoriesParams{
		ScanID:          scanID,
		SeverityFilters: severityFilters,
	}
	categoryData, err := s.vulnRepo.GetVulnerabilityCategoriesByScan(ctx, catParams)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch category data: %w", err)
	}
	summaryData.CategoryData = categoryData

	// 4. Get Host Trend Data
	trendParams := dto.VulnerabilityTrendsParams{
		HostID:           scan.HostID,
		TimePeriodFilter: timePeriodFilter,
		SeverityFilters:  severityFilters,
	}
	timePeriods, err := s.vulnRepo.GetHostVulnerabilityTrends(ctx, trendParams)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability trends for host %s: %w", scan.HostID.String(), err)
	}
	vulnerabilityTrends := domain.ServiceVulnerabilityTrends{
		TimePeriods: timePeriods,
	}

	// 4.1 Calculate TotalVulnCount and PeriodCount for the time period
	var totalVulnCountForAvg, periodCountForAvg float64
	for _, periodData := range timePeriods {
		if periodData.VulnerabilityCount != nil {
			totalVulnCountForAvg += float64(*periodData.VulnerabilityCount)
			periodCountForAvg++
		}
	}
	if periodCountForAvg > 0 {
		vulnerabilityTrends.AverageVulnerabilityCount = totalVulnCountForAvg / periodCountForAvg
	} else {
		vulnerabilityTrends.AverageVulnerabilityCount = 0.0
	}
	summaryData.VulnerabilityTrends = vulnerabilityTrends

	return &summaryData, nil
}

func (s *ScanService) GetAllReportsForTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.ReportItem, error) {
	reportItems, err := s.scanRepo.GetReportsByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch reports from storage: %w", err)
	}

	return reportItems, nil
}

func (s *ScanService) GetScoreCardTrendsForTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	fromDate, toDate *time.Time,
) ([]*domain.ScoreCardTrendItem, error) {
	hosts, err := s.hostRepo.GetHostsByTenantID(ctx, tenantID, []uuid.UUID{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch hosts for tenant %s: %w", tenantID, err)
	}

	scoreCardItems := make([]*domain.ScoreCardTrendItem, 0, len(hosts))
	for _, host := range hosts {
		oldestScan, latestScan, err := s.getOldestLatestScans(ctx, host.ID, fromDate, toDate)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch oldest and latest scan: %w", err)
		}

		var oldestProtectionScore, latestProtectionScore *float64
		if oldestScan != nil {
			oldScore, err := s.scanRepo.GetProtectionScore(ctx, oldestScan.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate oldest scan %s protection score: %w", oldestScan.ID.String(), err)
			}
			oldestProtectionScore = &oldScore
		}

		if latestScan != nil {
			latestScore, err := s.scanRepo.GetProtectionScore(ctx, latestScan.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate latest scan %s protection score: %w", latestScan.ID.String(), err)
			}
			latestProtectionScore = &latestScore
		}

		scoreCardItem := domain.NewScoreCardTrendItem(host.Name, oldestProtectionScore, latestProtectionScore)

		scoreCardItems = append(scoreCardItems, scoreCardItem)
	}

	return scoreCardItems, nil
}

func (s *ScanService) getOldestLatestScans(
	ctx context.Context,
	hostID uuid.UUID,
	fromDate, toDate *time.Time,
) (*domain.Scan, *domain.Scan, error) {
	oldestScan, err := s.scanRepo.GetOldestScanByHostID(ctx, hostID, fromDate, toDate)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("failed to get oldest scan: %w", err)
		}
	}
	latestScan, err := s.scanRepo.GetLatestScanByHostID(ctx, hostID, fromDate, toDate)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("failed to get latest scan: %w", err)
		}
	}

	// If the oldest scan and latest scan are the same, only return the latest scan
	if oldestScan != nil && latestScan != nil {
		if oldestScan.ID == latestScan.ID {
			return nil, latestScan, nil
		}
	}

	return oldestScan, latestScan, nil
}

func (s *ScanService) GetScanVulnerabilities(ctx context.Context, scanID uuid.UUID) ([]tools.Vulnerability, error) {
	return s.vulnRepo.GetVulnerabilitiesWithCveDetailByScanID(ctx, scanID)
}

func (s *ScanService) GetSeverityCounts(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	return s.vulnRepo.GetSeverityCountsByScanID(ctx, scanID)
}

func (s *ScanService) GetSeverityOSCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	return s.vulnRepo.GetSeverityOSCountsByScanID(ctx, scanID)
}

func (s *ScanService) GetSeverityServiceCountsByScanID(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
	return s.vulnRepo.GetSeverityServiceCountsByScanID(ctx, scanID)
}

func (s *ScanService) GetSeverityServiceCountsByScanAndServiceID(ctx context.Context, scanID uuid.UUID, serviceID int32) (tools.SeverityCounts, error) {
	return s.vulnRepo.GetSeverityServiceCountsByScanAndServiceID(ctx, scanID, serviceID)
}

func (s *ScanService) GetScanRapporteursAndHostAlias(ctx context.Context, scanID uuid.UUID) ([]domain.Rapporteur, string, error) {
	scan, err := s.scanRepo.GetScanByID(ctx, scanID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get scan by ID: %w", err)
	}
	host, err := s.hostRepo.GetHostByID(ctx, scan.HostID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get host by ID: %w", err)
	}
	return host.Rapporteurs, host.Name, nil
}

func (s *ScanService) GetSeverityCountsFromToolVulns(ctx context.Context, vulns []tools.Vulnerability) tools.SeverityCounts {
	domainVulners := domain.ConvertToolsToDomainVulnerabilities(vulns)
	return domain.CountSeverityOccurrencesGeneric(domainVulners)
}

func (s *ScanService) GetSeverityCountsFromDomainVulnDetail(ctx context.Context, vulns []domain.ScanVulnerabilityDetail) tools.SeverityCounts {
	return domain.CountSeverityOccurrencesGeneric(vulns)
}

func (s *ScanService) GetInformationGatheredResults(ctx context.Context, scanID uuid.UUID) ([]domain.ScanResult, error) {
	toolNames := []string{enums.ToolDNSLookup.String(), enums.ToolWhoIs.String(), enums.ToolHarvester.String()}
	result, err := s.scanResultsRepo.GetScanResultsByScanID(ctx, scanID, toolNames)
	if err != nil {
		slog.Debug("Failed to get scan results", slog.String("scanID", scanID.String()), slog.Any("toolNames", toolNames))
		return nil, err
	}
	return result, nil
}

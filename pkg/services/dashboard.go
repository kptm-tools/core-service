package services

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type DashboardService struct {
	vulnRepo interfaces.VulnerabilityRepository
	scanRepo interfaces.ScanRepository
	hostRepo interfaces.HostRepository
}

var _ interfaces.IDashboardService = (*DashboardService)(nil)

func NewDashboardService(
	vulnerabilityRepository interfaces.VulnerabilityRepository,
	scanRepository interfaces.ScanRepository,
	hostRepository interfaces.HostRepository,
) *DashboardService {
	return &DashboardService{
		vulnRepo: vulnerabilityRepository,
		scanRepo: scanRepository,
		hostRepo: hostRepository,
	}
}

// GetTenantDashboardData gets the Dashboard data for that Tenant.
// An important thing to note is that data is seen per host and it's latest scans.
// If a host has no latest scan, it's data is skipped for certain graphs such as the heatMap
// and # of vulnerabilities in HostsWithGreatestVulnerabilities, since saying no vulnerabilities
// were found would be misleading, because the data just doesn't exist at that moment.
func (s *DashboardService) GetTenantDashboardData(
	ctx context.Context,
	tenantID uuid.UUID,
	trendsTimePeriodFilter domain.TimePeriodFilter,
	trendsSeverityFilters []string,
	hostsIDFilter []uuid.UUID,
) (*domain.TenantDashboardData, error) {
	// 1. Get Overall Security Posture (averageProtectionScore)
	securityPostureData, err := s.GetTenantSecurityPosture(ctx, tenantID, hostsIDFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant security posture: %w", err)
	}

	// 2. Populate a map[domain.Host]domain.Scan with all latest scans for later reference
	hosts, err := s.hostRepo.GetHostsByTenantID(ctx, tenantID, hostsIDFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosts by tenantID %s: %w", tenantID, err)
	}

	hostLatestScanMap, err := s.getHostLatestScanMap(ctx, hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to getHostLatestScanMap: %w", err)
	}

	// 3. Calculate the Heat Map
	heatMap, err := s.getHostSeverityHeatMap(ctx, hosts, hostLatestScanMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get HostSeverityHeatMap: %w", err)
	}

	// 4. Calculate Overall Vulnerability Trends
	// 4.1 Get a slice with HostIDs to pass to GetHostsVulnerabilityTrends
	hostIDs := make([]uuid.UUID, 0, len(hosts))
	for _, host := range hosts {
		hostIDs = append(hostIDs, host.ID)
	}

	trendsTimePeriods, err := s.GetHostsVulnerabilityTrends(ctx, hostIDs, trendsTimePeriodFilter, trendsSeverityFilters)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability trends for hosts: %w", err)
	}

	// 5. Calculate Last Scan's Data
	latestScans := make([]*domain.Scan, 0, len(hostLatestScanMap))
	for _, scan := range hostLatestScanMap {
		latestScans = append(latestScans, scan)
	}

	latestScanData, err := s.getLatestScanData(ctx, latestScans)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest scan data: %w", err)
	}
	if latestScanData == nil {
		slog.Warn("Main Dashboard - No latest scan data was found, returning nil")
	}

	// 6. Calculate HostsWithGreatestVulnerabilities
	sortedHostsWithGreatestVulnerabilities, err := s.GetHostsSortedByMostVulnerabilities(ctx, hosts, hostLatestScanMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get sortedHostsWithGreatesVulnerabilities: %w", err)
	}

	dashboardData := domain.TenantDashboardData{
		OverallSecurityPosture:           *securityPostureData,
		HostSeverityHeatMap:              heatMap,
		VulnerabilityTrends:              trendsTimePeriods,
		LastScan:                         latestScanData, // Might be nil if there's no last scan
		HostsWithGreatestVulnerabilities: sortedHostsWithGreatestVulnerabilities,
	}

	return &dashboardData, nil
}

func (s *DashboardService) getHostLatestScanMap(
	ctx context.Context,
	hosts []*domain.Host,
) (map[uuid.UUID]*domain.Scan, error) {
	hostLatestScanMap := make(map[uuid.UUID]*domain.Scan, len(hosts))
	for _, host := range hosts {
		latestScan, err := s.scanRepo.GetLatestScanByHostID(ctx, host.ID, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get last scan for host %s: %w", host.ID, err)
		}
		if latestScan == nil {
			slog.Debug(
				"No scans found for host",
				slog.String("host_id", host.ID.String()),
			)
			// Skip hosts without scans - they won't be included in the map
			continue
		}
		hostLatestScanMap[host.ID] = latestScan
	}

	return hostLatestScanMap, nil
}

func (s *DashboardService) GetTenantSecurityPosture(
	ctx context.Context,
	tenantID uuid.UUID,
	hostsIDFilter []uuid.UUID,
) (*domain.OverallSecurityPostureData, error) {
	hosts, err := s.hostRepo.GetHostsByTenantID(ctx, tenantID, hostsIDFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosts for tenant %s: %w", tenantID, err)
	}

	currentScoreSum := 0.0
	currentHostCount := 0
	previousScoreSum := 0.0
	previousHostCount := 0

	for _, host := range hosts {
		latestScan, err := s.scanRepo.GetLatestScanByHostID(ctx, host.ID, nil, nil)
		if err != nil {
			slog.Warn(
				"Error getting latest scan for host",
				slog.String("host_id", host.ID.String()),
				slog.Any("error", err),
			)
			continue
		}
		if latestScan == nil {
			// No scans for this host yet, skip
			continue
		}

		if latestScan.ProtectionScore != nil {
			currentScoreSum += *latestScan.ProtectionScore
			currentHostCount++
		}

		previousScan, err := s.scanRepo.GetPreviousScan(ctx, latestScan.ID)
		if err != nil {
			slog.Warn(
				"Error getting scan before latest for host",
				slog.String("host_id", host.ID.String()),
				slog.Any("error", err),
			)
			continue
		}
		if previousScan != nil && previousScan.ProtectionScore != nil {
			previousScoreSum += *previousScan.ProtectionScore
			previousHostCount++
		}
	}

	var currentOverallScore float64 = 0
	if currentHostCount > 0 {
		currentOverallScore = currentScoreSum / float64(currentHostCount)
	}

	var previousOverallScore float64 = 0
	if previousHostCount > 0 {
		previousOverallScore = previousScoreSum / float64(previousHostCount)
	}

	variation := currentOverallScore - previousOverallScore

	return &domain.OverallSecurityPostureData{
		Score:     currentOverallScore,
		Variation: variation,
	}, nil
}

// getHostSeverityHeatMap returns a heatmap with the amount of severities found for each host.
// In case a host has no scans, it is skipped, to avoid giving the false impression that said host
// has no vulnerabilities (it just doesn't have data yet).
func (s *DashboardService) getHostSeverityHeatMap(
	ctx context.Context,
	hosts []*domain.Host,
	hostLatestScanMap map[uuid.UUID]*domain.Scan,
) ([]domain.HostAliasSeverityCountPair, error) {
	severityHeatMap := make([]domain.HostAliasSeverityCountPair, 0, len(hosts))
	for _, host := range hosts {
		if host == nil {
			continue
		}

		if scan, ok := hostLatestScanMap[host.ID]; ok {
			if scan == nil {
				continue
			}
			severityCounts, err := s.vulnRepo.GetSeverityCountsByScanID(ctx, scan.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to get host severity counts: %w", err)
			}
			severityHeatMap = append(severityHeatMap,
				domain.HostAliasSeverityCountPair{
					Alias:         host.Name,
					SeverityCount: severityCounts,
				})
		}
	}

	return severityHeatMap, nil
}

func (s *DashboardService) GetHostsVulnerabilityTrends(
	ctx context.Context,
	hostIDs []uuid.UUID,
	timePeriodFilter domain.TimePeriodFilter,
	severityFilters []string,
) ([]domain.ServiceTimePeriod, error) {
	orderedTimePeriods := timePeriodFilter.GetOrderedTimePeriods()

	aggregatedTimePeriods := make([]domain.ServiceTimePeriod, len(orderedTimePeriods))
	for i, period := range orderedTimePeriods {
		aggregatedTimePeriods[i] = domain.ServiceTimePeriod{
			TimePeriod:         period,
			VulnerabilityCount: nil, // Allocated as nil initially
		}
	}

	// Map for quick lookup of time period index in aggregatedTimePeriods
	periodIndexMap := make(map[string]int)
	for i, periodData := range aggregatedTimePeriods {
		periodIndexMap[periodData.TimePeriod] = i
	}

	for _, hostID := range hostIDs {
		params := dto.VulnerabilityTrendsParams{
			HostID:           hostID,
			TimePeriodFilter: timePeriodFilter,
			SeverityFilters:  severityFilters,
		}
		hostTrends, err := s.vulnRepo.GetHostVulnerabilityTrends(ctx, params)
		if err != nil {
			return nil, fmt.Errorf("failed to get trends for hostID %d: %w", hostID, err)
		}

		// Aggregate trends to the pre-ordered slice
		for _, periodData := range hostTrends {
			if index, ok := periodIndexMap[periodData.TimePeriod]; ok {
				if periodData.VulnerabilityCount != nil {
					if aggregatedTimePeriods[index].VulnerabilityCount == nil {
						aggregatedTimePeriods[index].VulnerabilityCount = periodData.VulnerabilityCount
					} else {
						*aggregatedTimePeriods[index].VulnerabilityCount += *periodData.VulnerabilityCount
					}
				}
			} else {
				slog.Error("Unexpected time period",
					slog.String("time_period", periodData.TimePeriod),
					slog.String("time_period_filter", timePeriodFilter.String()))
			}
		}
	}

	return aggregatedTimePeriods, nil
}

func (s *DashboardService) getLatestScanData(
	ctx context.Context,
	scans []*domain.Scan,
) (*domain.LastScanData, error) {
	// 5.1 Loop over hostLatestScanMap and get the one with the latest date
	var latestScan *domain.Scan
	var latestDate time.Time // Starts as zero-value for time.Time
	for _, scan := range scans {
		if scan == nil {
			continue
		}
		if scan.StartedAt.After(latestDate) {
			latestScan = scan
			latestDate = scan.StartedAt
		}
	}

	// If there's no latest scan, return nil
	if latestScan == nil {
		return nil, nil
	}

	// 5.2 Get severity counts for that scan
	latestScanInsights, err := s.scanRepo.GetScanInsightsBaseData(ctx, latestScan.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get severityCounts for latest scan %s: %w", latestScan.ID.String(), err)
	}

	// 5.3 Get base insights for previous scan to calculate variation
	vulnVariation := 0
	previousScan, err := s.scanRepo.GetPreviousScan(ctx, latestScan.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous scan: %w", err)
	}
	if previousScan != nil {
		previousTotalVulns, err := s.vulnRepo.GetVulnerabilityCountByScanID(ctx, previousScan.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get total vulnerabilities for previous scan %s: %w", previousScan.ID.String(), err)
		}
		vulnVariation = latestScanInsights.TotalVulnerabilities - previousTotalVulns
	}

	latestScanData := domain.LastScanData{
		HostAlias:                     latestScanInsights.HostAlias,
		TotalVulnerabilities:          latestScanInsights.TotalVulnerabilities,
		TotalVulnerabilitiesVariation: vulnVariation,
		SeverityCounts: tools.SeverityCounts{
			Unknown:  latestScanInsights.UnknownVulnerabilities,
			None:     latestScanInsights.NoneVulnerabilities,
			Low:      latestScanInsights.LowVulnerabilities,
			Medium:   latestScanInsights.MediumVulnerabilities,
			High:     latestScanInsights.HighVulnerabilities,
			Critical: latestScanInsights.CriticalVulnerabilities,
		},
		ScanDate: latestScanInsights.ScanDate,
	}

	return &latestScanData, nil
}

func (s *DashboardService) GetHostsSortedByMostVulnerabilities(
	ctx context.Context,
	hosts []*domain.Host,
	latestScanMap map[uuid.UUID]*domain.Scan,
) ([]domain.HostAliasVulnerabilityPair, error) {
	hostVulnerabilityPairs := []domain.HostAliasVulnerabilityPair{}

	// For quick lookup by ID
	hostMap := make(map[uuid.UUID]*domain.Host)
	for _, host := range hosts {
		hostMap[host.ID] = host
	}

	for hostID, scan := range latestScanMap {
		if scan == nil {
			continue
		}

		host := hostMap[hostID]
		vulnerabilityCount, err := s.vulnRepo.GetVulnerabilityCountByScanID(ctx, scan.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to count scan %s vulnerabilities: %w", scan.ID.String(), err)
		}

		hostVulnerabilityPairs = append(hostVulnerabilityPairs,
			domain.HostAliasVulnerabilityPair{Alias: host.Name, VulnerabilityCount: vulnerabilityCount},
		)
	}

	// Sort in descending order of vulnerability count
	sort.Slice(hostVulnerabilityPairs, func(i, j int) bool {
		if hostVulnerabilityPairs[i].VulnerabilityCount != hostVulnerabilityPairs[j].VulnerabilityCount {
			return hostVulnerabilityPairs[i].VulnerabilityCount > hostVulnerabilityPairs[j].VulnerabilityCount
		}
		return hostVulnerabilityPairs[i].Alias < hostVulnerabilityPairs[j].Alias
	})

	return hostVulnerabilityPairs, nil
}

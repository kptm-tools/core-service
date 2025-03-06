package services

import (
	"fmt"
	"log/slog"

	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type TenantService struct {
	storage interfaces.IStorage
}

var _ interfaces.ITenantService = (*TenantService)(nil)

func NewTenantService(storage interfaces.IStorage) *TenantService {
	return &TenantService{
		storage: storage,
	}
}

func (s *TenantService) CreateTenant(t *domain.Tenant) (*domain.Tenant, error) {
	return s.storage.CreateTenant(t)
}

func (s *TenantService) GetTenants() ([]*domain.Tenant, error) {
	tenants, err := s.storage.GetTenants()
	if err != nil {
		return nil, err
	}

	return tenants, nil
}

func (s *TenantService) GetTenantDashboardData(tenantID string) (*domain.TenantDashboardData, error) {
	// 1. Get Overall Security Posture (averageProtectionScore)
	overallSecurityPosture, securityPostureVariation, err := s.GetTenantSecurityPosture(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant security posture: %w", err)
	}

	securityPostureData := domain.OverallSecurityPostureData{
		Score:     overallSecurityPosture,
		Variation: securityPostureVariation,
	}

	// 2. Populate a map[domain.Host]domain.Scan with all latest scans for later reference
	hosts, err := s.storage.GetHostsByTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get hosts by tenantID %s: %w", tenantID, err)
	}

	hostLatestScanMap, err := s.getHostLatestScanMap(hosts)
	if err != nil {
		return nil, fmt.Errorf("failed to getHostLatestScanMap: %w", err)
	}

	// 3. Calculate the Heat Map
	heatMap, err := s.getHostSeverityHeatMap(hosts, hostLatestScanMap)
	if err != nil {
		return nil, fmt.Errorf("failed to get HostSeverityHeatMap: %w", err)
	}

	// 4. Calculate Overall Vulnerability Trends
	// 4.1 Get a slice with HostIDs to pass to GetHostsVulnerabilityTrends
	hostIDs := make([]int, 0, len(hosts))
	for _, host := range hosts {
		hostIDs = append(hostIDs, host.ID)
	}

	trendsTimePeriods, err := s.GetHostsVulnerabilityTrends(hostIDs, "Month", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerability trends for hosts: %w", err)
	}
	// 5. Calculate Last Scan's Data
	// 6. Calculate HostsWithGreatestVulnerabilities

	dashboardData := domain.TenantDashboardData{
		OverallSecurityPosture: securityPostureData,
		HostSeverityHeatMap:    heatMap,
		VulnerabilityTrends:    trendsTimePeriods,
	}

	return &dashboardData, nil
}

func (s *TenantService) getHostLatestScanMap(hosts []*domain.Host) (map[int]*domain.Scan, error) {
	hostLatestScanMap := make(map[int]*domain.Scan, len(hosts))
	for _, host := range hosts {
		latestScan, err := s.storage.GetLatestScanByHostID(host.ID, nil, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get last scan for host %d: %w", host.ID, err)
		}
		if latestScan == nil {
			slog.Warn(
				"LatestScan for host is nil",
				slog.Int("host_id", host.ID),
			)
		}
		hostLatestScanMap[host.ID] = latestScan
	}

	return hostLatestScanMap, nil
}

func (s *TenantService) GetTenantSecurityPosture(tenantID string) (float64, float64, error) {
	hosts, err := s.storage.GetHostsByTenantID(tenantID)
	if err != nil {
		return 0.0, 0.0, fmt.Errorf("failed to get hosts for tenant %s: %w", tenantID, err)
	}

	currentScoreSum := 0.0
	currentHostCount := 0
	previousScoreSum := 0.0
	previousHostCount := 0

	for _, host := range hosts {
		latestScan, err := s.storage.GetLatestScanByHostID(host.ID, nil, nil)
		if err != nil {
			slog.Warn(
				"Error getting latest scan for host",
				slog.Int("host_id", host.ID),
				slog.Any("error", err),
			)
			continue
		}
		if latestScan != nil {
			currentScoreSum += *latestScan.ProtectionScore
			currentHostCount++
		}

		previousScan, err := s.storage.GetScanBeforeLatestByHostID(host.ID, nil, nil)
		if err != nil {
			slog.Warn(
				"Error getting scan before latest for host",
				slog.Int("host_id", host.ID),
				slog.Any("error", err),
			)
			continue
		}
		if previousScan != nil {
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

	return currentOverallScore, variation, nil
}

func (s *TenantService) getHostSeverityHeatMap(hosts []*domain.Host, hostLatestScanMap map[int]*domain.Scan) (domain.HostSeverityHeatMapData, error) {
	severityHeatMap := make(domain.HostSeverityHeatMapData, len(hosts))
	slog.Debug("GetHostSeverityHeatMap:", slog.Any("host_latest_scan_map", hostLatestScanMap))
	for _, host := range hosts {
		if host == nil {
			continue
		}

		if scan, ok := hostLatestScanMap[host.ID]; ok {
			if scan != nil {
				severityCounts, err := s.storage.GetSeverityCounts(scan.ID)
				if err != nil {
					return nil, fmt.Errorf("failed to get host severity counts: %w", err)
				}
				severityHeatMap[host.Name] = *severityCounts
			} else {
				severityHeatMap[host.Name] = tools.SeverityCounts{}
			}
		}
	}

	return severityHeatMap, nil
}

func (s *TenantService) GetHostsVulnerabilityTrends(
	hostIDs []int,
	timePeriodFilter string,
	severityFilters []string,
) ([]domain.ServiceTimePeriod, error) {
	aggregatedTrendsMap := make(map[string]int)

	for _, hostID := range hostIDs {
		hostTrends, err := s.storage.GetHostVulnerabilityTrends(hostID, timePeriodFilter, severityFilters)
		if err != nil {
			return nil, fmt.Errorf("failed to get trends for hostID %d: %w", hostID, err)
		}

		// Aggregate trends from the current host into the overall map
		for _, periodData := range hostTrends {
			aggregatedTrendsMap[periodData.TimePeriod] += periodData.VulnerabilityCount
		}
	}

	// Convert the aggregated map to a []domain.ServiceTimePeriod slice
	var aggregatedTimePeriods []domain.ServiceTimePeriod
	for timePeriod, vulnCount := range aggregatedTrendsMap {
		aggregatedTimePeriods = append(aggregatedTimePeriods, domain.ServiceTimePeriod{
			TimePeriod:         timePeriod,
			VulnerabilityCount: vulnCount,
		})
	}

	return aggregatedTimePeriods, nil
}

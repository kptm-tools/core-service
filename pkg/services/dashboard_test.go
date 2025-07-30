package services_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
	mock "github.com/kptm-tools/core-service/pkg/mocks/storage"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDashboardService_GetTenantDashboardData_NoHosts(t *testing.T) {
	// Setup
	tenantID := uuid.New()
	ctx := context.Background()

	mockHostRepo := &mock.MockHostRepo{
		MockGetHostsByTenantID: func(ctx context.Context, tid uuid.UUID, hostIDFilter []uuid.UUID) ([]*domain.Host, error) {
			return []*domain.Host{}, nil
		},
	}

	mockScanRepo := &mock.MockScanRepo{}
	mockVulnRepo := &mock.MockVulnerabilityRepo{}

	service := services.NewDashboardService(mockVulnRepo, mockScanRepo, mockHostRepo)

	// Execute
	result, err := service.GetTenantDashboardData(ctx, tenantID, domain.TimePeriodFilterMonth, nil, nil)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, float64(0), result.OverallSecurityPosture.Score)
	assert.Empty(t, result.HostSeverityHeatMap)
	assert.Empty(t, result.HostsWithGreatestVulnerabilities)
	assert.Nil(t, result.LastScan)
}

func TestDashboardService_GetTenantDashboardData_HostsWithoutScans(t *testing.T) {
	// Setup
	tenantID := uuid.New()
	ctx := context.Background()

	hosts := []*domain.Host{
		{
			ID:       uuid.New(),
			TenantID: tenantID,
			Name:     "Host1",
		},
		{
			ID:       uuid.New(),
			TenantID: tenantID,
			Name:     "Host2",
		},
	}

	mockHostRepo := &mock.MockHostRepo{
		MockGetHostsByTenantID: func(ctx context.Context, tid uuid.UUID, hostIDFilter []uuid.UUID) ([]*domain.Host, error) {
			return hosts, nil
		},
	}

	mockScanRepo := &mock.MockScanRepo{
		MockGetLatestScanByHostID: func(ctx context.Context, hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
			// All hosts have no scans
			return nil, nil
		},
	}

	mockVulnRepo := &mock.MockVulnerabilityRepo{
		MockGetHostVulnerabilityTrends: func(ctx context.Context, params dto.VulnerabilityTrendsParams) ([]domain.ServiceTimePeriod, error) {
			return []domain.ServiceTimePeriod{}, nil
		},
	}

	service := services.NewDashboardService(mockVulnRepo, mockScanRepo, mockHostRepo)

	// Execute
	result, err := service.GetTenantDashboardData(ctx, tenantID, domain.TimePeriodFilterMonth, nil, nil)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, float64(0), result.OverallSecurityPosture.Score)
	assert.Empty(t, result.HostSeverityHeatMap)
	assert.Empty(t, result.HostsWithGreatestVulnerabilities)
	assert.Nil(t, result.LastScan)
}

func TestDashboardService_GetTenantDashboardData_MixedHostsWithAndWithoutScans(t *testing.T) {
	// Setup
	tenantID := uuid.New()
	ctx := context.Background()

	hosts := []*domain.Host{
		{
			ID:       uuid.New(),
			TenantID: tenantID,
			Name:     "HostWithScan",
		},
		{
			ID:       uuid.New(),
			TenantID: tenantID,
			Name:     "HostWithoutScan",
		},
	}

	scanID := uuid.New()
	protectionScore := 0.85
	scan := &domain.Scan{
		ID:              scanID,
		HostID:          hosts[0].ID,
		TenantID:        tenantID,
		StartedAt:       time.Now().Add(-24 * time.Hour),
		ProtectionScore: &protectionScore,
		Status:          "Completed",
	}

	mockHostRepo := &mock.MockHostRepo{
		MockGetHostsByTenantID: func(ctx context.Context, tid uuid.UUID, hostIDFilter []uuid.UUID) ([]*domain.Host, error) {
			return hosts, nil
		},
	}

	mockScanRepo := &mock.MockScanRepo{
		MockGetLatestScanByHostID: func(ctx context.Context, hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
			if hostID == hosts[0].ID {
				return scan, nil
			}
			return nil, nil // No scan for the second host
		},
		MockGetPreviousScan: func(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
			return nil, nil // No previous scan
		},
		MockGetScanInsightsBaseData: func(ctx context.Context, scanID uuid.UUID) (domain.ScanInsightsBaseData, error) {
			return domain.ScanInsightsBaseData{
				ScanID:                  scanID,
				HostAlias:               "HostWithScan",
				ScanDate:                scan.StartedAt,
				TotalVulnerabilities:    10,
				CriticalVulnerabilities: 2,
				HighVulnerabilities:     3,
				MediumVulnerabilities:   3,
				LowVulnerabilities:      2,
				NoneVulnerabilities:     0,
				UnknownVulnerabilities:  0,
			}, nil
		},
	}

	mockVulnRepo := &mock.MockVulnerabilityRepo{
		MockGetSeverityCountsByScanID: func(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
			return tools.SeverityCounts{
				Critical: 2,
				High:     3,
				Medium:   3,
				Low:      2,
				None:     0,
				Unknown:  0,
			}, nil
		},
		MockGetVulnerabilityCountByScanID: func(ctx context.Context, scanID uuid.UUID) (int, error) {
			return 10, nil
		},
		MockGetHostVulnerabilityTrends: func(ctx context.Context, params dto.VulnerabilityTrendsParams) ([]domain.ServiceTimePeriod, error) {
			count := 10
			return []domain.ServiceTimePeriod{
				{
					TimePeriod:         "July",
					VulnerabilityCount: &count,
				},
			}, nil
		},
	}

	service := services.NewDashboardService(mockVulnRepo, mockScanRepo, mockHostRepo)

	// Execute
	result, err := service.GetTenantDashboardData(ctx, tenantID, domain.TimePeriodFilterMonth, nil, nil)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, protectionScore, result.OverallSecurityPosture.Score)
	assert.Len(t, result.HostSeverityHeatMap, 1) // Only one host has scans
	assert.Equal(t, "HostWithScan", result.HostSeverityHeatMap[0].Alias)
	assert.Len(t, result.HostsWithGreatestVulnerabilities, 1)
	assert.NotNil(t, result.LastScan)
	assert.Equal(t, "HostWithScan", result.LastScan.HostAlias)
	assert.Equal(t, 10, result.LastScan.TotalVulnerabilities)
}

func TestDashboardService_GetTenantDashboardData_ErrorGettingHosts(t *testing.T) {
	// Setup
	tenantID := uuid.New()
	ctx := context.Background()

	mockHostRepo := &mock.MockHostRepo{
		MockGetHostsByTenantID: func(ctx context.Context, tid uuid.UUID, hostIDFilter []uuid.UUID) ([]*domain.Host, error) {
			return nil, errors.New("database error")
		},
	}

	mockScanRepo := &mock.MockScanRepo{}
	mockVulnRepo := &mock.MockVulnerabilityRepo{}

	service := services.NewDashboardService(mockVulnRepo, mockScanRepo, mockHostRepo)

	// Execute
	result, err := service.GetTenantDashboardData(ctx, tenantID, domain.TimePeriodFilterMonth, nil, nil)

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get hosts for tenant")
	assert.Nil(t, result)
}

func TestDashboardService_GetTenantSecurityPosture_WithPreviousScans(t *testing.T) {
	// Setup
	tenantID := uuid.New()
	ctx := context.Background()

	hosts := []*domain.Host{
		{ID: uuid.New(), TenantID: tenantID, Name: "Host1"},
		{ID: uuid.New(), TenantID: tenantID, Name: "Host2"},
	}

	currentScore1 := 0.8
	currentScore2 := 0.9
	previousScore1 := 0.7
	previousScore2 := 0.75

	currentScan1 := &domain.Scan{
		ID:              uuid.New(),
		ProtectionScore: &currentScore1,
	}
	currentScan2 := &domain.Scan{
		ID:              uuid.New(),
		ProtectionScore: &currentScore2,
	}
	previousScan1 := &domain.Scan{
		ID:              uuid.New(),
		ProtectionScore: &previousScore1,
	}
	previousScan2 := &domain.Scan{
		ID:              uuid.New(),
		ProtectionScore: &previousScore2,
	}

	mockHostRepo := &mock.MockHostRepo{
		MockGetHostsByTenantID: func(ctx context.Context, tid uuid.UUID, hostIDFilter []uuid.UUID) ([]*domain.Host, error) {
			return hosts, nil
		},
	}

	mockScanRepo := &mock.MockScanRepo{
		MockGetLatestScanByHostID: func(ctx context.Context, hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
			if hostID == hosts[0].ID {
				return currentScan1, nil
			}
			if hostID == hosts[1].ID {
				return currentScan2, nil
			}
			return nil, nil
		},
		MockGetPreviousScan: func(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
			if scanID == currentScan1.ID {
				return previousScan1, nil
			}
			if scanID == currentScan2.ID {
				return previousScan2, nil
			}
			return nil, nil
		},
	}

	service := services.NewDashboardService(nil, mockScanRepo, mockHostRepo)

	// Execute
	result, err := service.GetTenantSecurityPosture(ctx, tenantID, nil)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)

	expectedCurrentScore := (currentScore1 + currentScore2) / 2
	expectedPreviousScore := (previousScore1 + previousScore2) / 2
	expectedVariation := expectedCurrentScore - expectedPreviousScore

	assert.Equal(t, expectedCurrentScore, result.Score)
	assert.Equal(t, expectedVariation, result.Variation)
}

func TestDashboardService_GetHostsVulnerabilityTrends_MultipleHosts(t *testing.T) {
	// Setup
	ctx := context.Background()
	hostIDs := []uuid.UUID{uuid.New(), uuid.New()}

	count1 := 5
	count2 := 10
	count3 := 5 // Separate variable for June in trends2
	// Return month names as expected by GetOrderedTimePeriods
	trends1 := []domain.ServiceTimePeriod{
		{TimePeriod: "July", VulnerabilityCount: &count1},
		{TimePeriod: "June", VulnerabilityCount: nil}, // No data for this period
	}
	trends2 := []domain.ServiceTimePeriod{
		{TimePeriod: "July", VulnerabilityCount: &count2},
		{TimePeriod: "June", VulnerabilityCount: &count3},
	}

	callCount := 0
	mockVulnRepo := &mock.MockVulnerabilityRepo{
		MockGetHostVulnerabilityTrends: func(ctx context.Context, params dto.VulnerabilityTrendsParams) ([]domain.ServiceTimePeriod, error) {
			if callCount == 0 {
				callCount++
				return trends1, nil
			}
			return trends2, nil
		},
	}

	service := services.NewDashboardService(mockVulnRepo, nil, nil)

	// Execute
	result, err := service.GetHostsVulnerabilityTrends(ctx, hostIDs, domain.TimePeriodFilterMonth, nil)

	// Assert
	require.NoError(t, err)
	assert.Len(t, result, 12) // All 12 months are returned

	// Find July and June in results
	var julyResult, juneResult *domain.ServiceTimePeriod
	for i := range result {
		if result[i].TimePeriod == "July" {
			julyResult = &result[i]
		} else if result[i].TimePeriod == "June" {
			juneResult = &result[i]
		}
	}

	// Verify aggregation for July
	assert.NotNil(t, julyResult)
	assert.NotNil(t, julyResult.VulnerabilityCount)
	assert.Equal(t, 15, *julyResult.VulnerabilityCount) // 5 + 10

	// Verify aggregation for June
	assert.NotNil(t, juneResult)
	assert.NotNil(t, juneResult.VulnerabilityCount)
	assert.Equal(t, 5, *juneResult.VulnerabilityCount) // nil first gets assigned 5
}

func TestDashboardService_GetHostsSortedByMostVulnerabilities(t *testing.T) {
	// Setup
	ctx := context.Background()

	hosts := []*domain.Host{
		{ID: uuid.New(), Name: "Host1"},
		{ID: uuid.New(), Name: "Host2"},
		{ID: uuid.New(), Name: "Host3"},
	}

	scanMap := map[uuid.UUID]*domain.Scan{
		hosts[0].ID: {ID: uuid.New()},
		hosts[1].ID: {ID: uuid.New()},
		hosts[2].ID: nil, // Host without scan
	}

	mockVulnRepo := &mock.MockVulnerabilityRepo{
		MockGetVulnerabilityCountByScanID: func(ctx context.Context, scanID uuid.UUID) (int, error) {
			if scanID == scanMap[hosts[0].ID].ID {
				return 20, nil
			}
			if scanID == scanMap[hosts[1].ID].ID {
				return 30, nil
			}
			return 0, nil
		},
	}

	service := services.NewDashboardService(mockVulnRepo, nil, nil)

	// Execute
	result, err := service.GetHostsSortedByMostVulnerabilities(ctx, hosts, scanMap)

	// Assert
	require.NoError(t, err)
	assert.Len(t, result, 2) // Only 2 hosts have scans

	// Verify sorting (descending by vulnerability count)
	assert.Equal(t, "Host2", result[0].Alias)
	assert.Equal(t, 30, result[0].VulnerabilityCount)
	assert.Equal(t, "Host1", result[1].Alias)
	assert.Equal(t, 20, result[1].VulnerabilityCount)
}

func TestDashboardService_GetTenantDashboardData_CompleteScenario(t *testing.T) {
	// Setup - Complete scenario with all data
	tenantID := uuid.New()
	ctx := context.Background()

	hosts := []*domain.Host{
		{ID: uuid.New(), TenantID: tenantID, Name: "ProdServer"},
		{ID: uuid.New(), TenantID: tenantID, Name: "TestServer"},
	}

	scanID1 := uuid.New()
	scanID2 := uuid.New()
	protectionScore1 := 0.75
	protectionScore2 := 0.90

	scan1 := &domain.Scan{
		ID:              scanID1,
		HostID:          hosts[0].ID,
		TenantID:        tenantID,
		StartedAt:       time.Now().Add(-2 * time.Hour),
		ProtectionScore: &protectionScore1,
		Status:          "Completed",
	}

	scan2 := &domain.Scan{
		ID:              scanID2,
		HostID:          hosts[1].ID,
		TenantID:        tenantID,
		StartedAt:       time.Now().Add(-1 * time.Hour), // More recent
		ProtectionScore: &protectionScore2,
		Status:          "Completed",
	}

	mockHostRepo := &mock.MockHostRepo{
		MockGetHostsByTenantID: func(ctx context.Context, tid uuid.UUID, hostIDFilter []uuid.UUID) ([]*domain.Host, error) {
			return hosts, nil
		},
	}

	mockScanRepo := &mock.MockScanRepo{
		MockGetLatestScanByHostID: func(ctx context.Context, hostID uuid.UUID, fromDate, toDate *time.Time) (*domain.Scan, error) {
			if hostID == hosts[0].ID {
				return scan1, nil
			}
			if hostID == hosts[1].ID {
				return scan2, nil
			}
			return nil, nil
		},
		MockGetPreviousScan: func(ctx context.Context, scanID uuid.UUID) (*domain.Scan, error) {
			return nil, nil // No previous scans
		},
		MockGetScanInsightsBaseData: func(ctx context.Context, scanID uuid.UUID) (domain.ScanInsightsBaseData, error) {
			if scanID == scan2.ID {
				return domain.ScanInsightsBaseData{
					ScanID:                  scanID,
					HostAlias:               "TestServer",
					ScanDate:                scan2.StartedAt,
					TotalVulnerabilities:    5,
					CriticalVulnerabilities: 0,
					HighVulnerabilities:     1,
					MediumVulnerabilities:   2,
					LowVulnerabilities:      2,
					NoneVulnerabilities:     0,
					UnknownVulnerabilities:  0,
				}, nil
			}
			return domain.ScanInsightsBaseData{}, errors.New("unexpected scan ID")
		},
	}

	mockVulnRepo := &mock.MockVulnerabilityRepo{
		MockGetSeverityCountsByScanID: func(ctx context.Context, scanID uuid.UUID) (tools.SeverityCounts, error) {
			if scanID == scan1.ID {
				return tools.SeverityCounts{
					Critical: 2,
					High:     5,
					Medium:   10,
					Low:      8,
					None:     0,
					Unknown:  0,
				}, nil
			}
			if scanID == scan2.ID {
				return tools.SeverityCounts{
					Critical: 0,
					High:     1,
					Medium:   2,
					Low:      2,
					None:     0,
					Unknown:  0,
				}, nil
			}
			return tools.SeverityCounts{}, nil
		},
		MockGetVulnerabilityCountByScanID: func(ctx context.Context, scanID uuid.UUID) (int, error) {
			if scanID == scan1.ID {
				return 25, nil
			}
			if scanID == scan2.ID {
				return 5, nil
			}
			return 0, nil
		},
		MockGetHostVulnerabilityTrends: func(ctx context.Context, params dto.VulnerabilityTrendsParams) ([]domain.ServiceTimePeriod, error) {
			var count int
			if params.HostID == hosts[0].ID {
				count = 25
			} else {
				count = 5
			}
			return []domain.ServiceTimePeriod{
				{
					TimePeriod:         "July",
					VulnerabilityCount: &count,
				},
			}, nil
		},
	}

	service := services.NewDashboardService(mockVulnRepo, mockScanRepo, mockHostRepo)

	// Execute
	result, err := service.GetTenantDashboardData(ctx, tenantID, domain.TimePeriodFilterMonth, nil, nil)

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Overall security posture
	expectedScore := (protectionScore1 + protectionScore2) / 2
	assert.Equal(t, expectedScore, result.OverallSecurityPosture.Score)
	assert.Equal(t, expectedScore, result.OverallSecurityPosture.Variation) // No previous scans means variation = current score

	// Heat map
	assert.Len(t, result.HostSeverityHeatMap, 2)

	// Vulnerability trends
	assert.Len(t, result.VulnerabilityTrends, 12) // All months are returned
	// Find July in results
	var julyTrend *domain.ServiceTimePeriod
	for i := range result.VulnerabilityTrends {
		if result.VulnerabilityTrends[i].TimePeriod == "July" {
			julyTrend = &result.VulnerabilityTrends[i]
			break
		}
	}
	assert.NotNil(t, julyTrend)
	assert.NotNil(t, julyTrend.VulnerabilityCount)
	assert.Equal(t, 30, *julyTrend.VulnerabilityCount) // 25 + 5

	// Last scan (should be the most recent one - scan2)
	assert.NotNil(t, result.LastScan)
	assert.Equal(t, "TestServer", result.LastScan.HostAlias)
	assert.Equal(t, 5, result.LastScan.TotalVulnerabilities)
	assert.Equal(t, 0, result.LastScan.TotalVulnerabilitiesVariation)

	// Hosts with greatest vulnerabilities
	assert.Len(t, result.HostsWithGreatestVulnerabilities, 2)
	assert.Equal(t, "ProdServer", result.HostsWithGreatestVulnerabilities[0].Alias)
	assert.Equal(t, 25, result.HostsWithGreatestVulnerabilities[0].VulnerabilityCount)
	assert.Equal(t, "TestServer", result.HostsWithGreatestVulnerabilities[1].Alias)
	assert.Equal(t, 5, result.HostsWithGreatestVulnerabilities[1].VulnerabilityCount)
}

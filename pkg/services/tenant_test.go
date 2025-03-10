package services

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/customerrors"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/mocks"
	"github.com/stretchr/testify/assert"
)

func Test_GetHostsSortedByMostVulnerabilities(t *testing.T) {
	testCases := []struct {
		name               string
		inputHosts         []*domain.Host
		inputLatestScanMap map[int]*domain.Scan
		mockSetup          func(mockStore *mocks.MockStorage)
		expected           []domain.HostAliasVulnerabilityPair
		expectErr          bool
	}{
		{
			name: "Two hosts with scans - same vulnerability count",
			inputHosts: []*domain.Host{
				{ID: 1, Name: "Host1"},
				{ID: 2, Name: "Host2"},
			},
			inputLatestScanMap: map[int]*domain.Scan{
				1: {ID: uuid.New()},
				2: {ID: uuid.New()},
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanVulnerabilityCount = func(scanID uuid.UUID) (int, error) {
					return 2, nil
				}
			},
			expected: []domain.HostAliasVulnerabilityPair{
				{Alias: "Host1", VulnerabilityCount: 2},
				{Alias: "Host2", VulnerabilityCount: 2},
			},
			expectErr: false,
		},
		{
			name: "Two hosts with scans - different vulnerability count",
			inputHosts: []*domain.Host{
				{ID: 1, Name: "Host1"},
				{ID: 2, Name: "Host2"},
			},
			inputLatestScanMap: map[int]*domain.Scan{
				1: {ID: uuid.MustParse("ba40e3a9-50bb-4b0c-b9e6-7a6385f3abbf")},
				2: {ID: uuid.MustParse("b1596ca0-d48a-4bfd-976a-22afb44f9b06")},
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				scanIDToVulnerabilityCount := make(map[uuid.UUID]int)
				scanID1 := uuid.MustParse("ba40e3a9-50bb-4b0c-b9e6-7a6385f3abbf")
				scanID2 := uuid.MustParse("b1596ca0-d48a-4bfd-976a-22afb44f9b06")
				scanIDToVulnerabilityCount[scanID1] = 5
				scanIDToVulnerabilityCount[scanID2] = 1

				mockStore.MockGetScanVulnerabilityCount = func(scanID uuid.UUID) (int, error) {
					if vulnCount, ok := scanIDToVulnerabilityCount[scanID]; ok {
						return vulnCount, nil
					}
					return 0, nil
				}
			},
			expected: []domain.HostAliasVulnerabilityPair{
				{Alias: "Host1", VulnerabilityCount: 5},
				{Alias: "Host2", VulnerabilityCount: 1},
			},
			expectErr: false,
		},
		{
			name: "Hosts with no scans",
			inputHosts: []*domain.Host{
				{ID: 1, Name: "Host1"},
				{ID: 2, Name: "Host2"},
			},
			inputLatestScanMap: map[int]*domain.Scan{
				1: nil,
				2: nil,
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanVulnerabilityCount = func(scanID uuid.UUID) (int, error) {
					return 0, nil
				}
			},
			expected:  []domain.HostAliasVulnerabilityPair{},
			expectErr: false,
		},
		{
			name: "Mixed hosts with and without scans",
			inputHosts: []*domain.Host{
				{ID: 1, Name: "Host1"},
				{ID: 2, Name: "Host2"},
			},
			inputLatestScanMap: map[int]*domain.Scan{
				1: {ID: uuid.New()},
				2: nil,
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanVulnerabilityCount = func(scanID uuid.UUID) (int, error) {
					return 2, nil
				}
			},
			expected: []domain.HostAliasVulnerabilityPair{
				{Alias: "Host1", VulnerabilityCount: 2},
			},
			expectErr: false,
		},
		{
			name: "Error from GetScanVulnerabilityCount",
			inputHosts: []*domain.Host{
				{ID: 1, Name: "Host1"},
				{ID: 2, Name: "Host2"},
			},
			inputLatestScanMap: map[int]*domain.Scan{
				1: {ID: uuid.New()},
				2: nil,
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanVulnerabilityCount = func(scanID uuid.UUID) (int, error) {
					return 0, customerrors.ErrScanNotFound
				}
			},
			expected:  []domain.HostAliasVulnerabilityPair{},
			expectErr: true,
		},
		{
			name:               "Empty input hosts and scans",
			inputHosts:         []*domain.Host{},
			inputLatestScanMap: map[int]*domain.Scan{},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanVulnerabilityCount = func(scanID uuid.UUID) (int, error) {
					return 0, nil
				}
			},
			expected:  []domain.HostAliasVulnerabilityPair{},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockStore := &mocks.MockStorage{}
			tc.mockSetup(mockStore)

			tenantService := NewTenantService(mockStore)
			aliasVulnerPairs, err := tenantService.GetHostsSortedByMostVulnerabilities(tc.inputHosts, tc.inputLatestScanMap)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, len(tc.expected), len(aliasVulnerPairs), "Expected number of HostAliasVulnerabilityPair does not match")

			sort.Slice(tc.expected, func(i, j int) bool {
				if tc.expected[i].VulnerabilityCount != tc.expected[j].VulnerabilityCount {
					return tc.expected[i].VulnerabilityCount > tc.expected[j].VulnerabilityCount
				}
				return tc.expected[i].Alias < tc.expected[j].Alias
			})

			for i, expectedPair := range tc.expected {
				assert.Equal(t, expectedPair.Alias, aliasVulnerPairs[i].Alias, "Alias mismatch at index %d", i)
				assert.Equal(t, expectedPair.VulnerabilityCount, aliasVulnerPairs[i].VulnerabilityCount, "VulnerabilityCount mismatch at index %d for Alias %s", i, expectedPair.Alias)
			}
		})
	}
}

func Test_getLatestScanData(t *testing.T) {
	timeNow := time.Now().UTC()

	testCases := []struct {
		name       string
		inputScans []*domain.Scan
		mockSetup  func(mockStore *mocks.MockStorage)
		expected   *domain.LastScanData
		expectErr  bool
	}{
		{
			name: "Two Valid Scans - Success",
			inputScans: []*domain.Scan{
				{
					ID:        uuid.MustParse("740cc333-80f8-40f0-b14b-466e3cbb77d0"),
					StartedAt: timeNow,
				},
				{
					ID:        uuid.MustParse("02ac2f74-8a0d-4804-a566-e7c06dfe180e"),
					StartedAt: timeNow.Add(time.Hour * -24),
				},
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanInsights = func(scanID uuid.UUID) (*domain.ScanInsights, error) {
					if scanID == uuid.MustParse("740cc333-80f8-40f0-b14b-466e3cbb77d0") {
						return &domain.ScanInsights{
							TotalVulnerabilities:   5,
							VulnerabilityVariation: 1,
							SeverityCounts: tools.SeverityCounts{
								Critical: 1,
								High:     1,
								Medium:   1,
								Low:      1,
								None:     0,
								Unknown:  0,
							},
							Metadata: domain.ScanInsightsMetadata{
								HostAlias: "Scan 740cc333-80f8-40f0-b14b-466e3cbb77d0 Host Alias",
								ScanDate:  timeNow,
							},
						}, nil
					}
					return nil, fmt.Errorf("No scan insights for scan")
				}
			},
			expected: &domain.LastScanData{
				HostAlias:                     "Scan 740cc333-80f8-40f0-b14b-466e3cbb77d0 Host Alias",
				TotalVulnerabilities:          5,
				TotalVulnerabilitiesVariation: 1,
				SeverityCounts: tools.SeverityCounts{
					Critical: 1,
					High:     1,
					Medium:   1,
					Low:      1,
					None:     0,
					Unknown:  0,
				},
				ScanDate: timeNow,
			},
			expectErr: false,
		},
		{
			name:       "Nil scans",
			inputScans: []*domain.Scan{nil, nil},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanInsights = func(scanID uuid.UUID) (*domain.ScanInsights, error) {
					return nil, nil
				}
			},
			expected:  nil,
			expectErr: false,
		},
		{
			name: "Scans with same date",
			inputScans: []*domain.Scan{
				{
					ID:        uuid.MustParse("740cc333-80f8-40f0-b14b-466e3cbb77d0"),
					StartedAt: timeNow,
				},
				{
					ID:        uuid.MustParse("02ac2f74-8a0d-4804-a566-e7c06dfe180e"),
					StartedAt: timeNow,
				},
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanInsights = func(scanID uuid.UUID) (*domain.ScanInsights, error) {
					if scanID == uuid.MustParse("740cc333-80f8-40f0-b14b-466e3cbb77d0") {
						return &domain.ScanInsights{
							Metadata: domain.ScanInsightsMetadata{
								HostAlias: "Host of Scan 740cc333-80f8-40f0-b14b-466e3cbb77d0",
							},
						}, nil
					}
					return &domain.ScanInsights{}, nil
				}
			},
			// We expect to get the first value of the slice, since we're comparing if
			// the date is AFTER
			expected: &domain.LastScanData{
				HostAlias: "Host of Scan 740cc333-80f8-40f0-b14b-466e3cbb77d0",
			},
			expectErr: false,
		},
		{
			name: "Scans Insights Error",
			inputScans: []*domain.Scan{
				{
					ID:        uuid.MustParse("740cc333-80f8-40f0-b14b-466e3cbb77d0"),
					StartedAt: timeNow,
				},
			},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanInsights = func(scanID uuid.UUID) (*domain.ScanInsights, error) {
					return nil, fmt.Errorf("Error connecting to database")
				}
			},
			expected:  nil,
			expectErr: true,
		},
		{
			name:       "No scans",
			inputScans: []*domain.Scan{},
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetScanInsights = func(scanID uuid.UUID) (*domain.ScanInsights, error) {
					return nil, nil
				}
			},
			expected:  nil,
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockStore := &mocks.MockStorage{}
			tc.mockSetup(mockStore)

			tenantService := NewTenantService(mockStore)
			lastScanData, err := tenantService.getLatestScanData(tc.inputScans)
			if tc.expectErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			if tc.expected == nil {
				assert.Nil(t, lastScanData)
				return
			}

			// Assert LastScanData is equal to expected struct
			assert.NotNil(t, lastScanData)
			assert.Equal(t, tc.expected.HostAlias, lastScanData.HostAlias)
			assert.Equal(t, tc.expected.TotalVulnerabilities, lastScanData.TotalVulnerabilities)
			assert.Equal(t, tc.expected.TotalVulnerabilitiesVariation, lastScanData.TotalVulnerabilitiesVariation)

			// SeverityCount sub-struct
			assert.Equal(t, tc.expected.SeverityCounts.Critical, lastScanData.SeverityCounts.Critical)
			assert.Equal(t, tc.expected.SeverityCounts.High, lastScanData.SeverityCounts.High)
			assert.Equal(t, tc.expected.SeverityCounts.Medium, lastScanData.SeverityCounts.Medium)
			assert.Equal(t, tc.expected.SeverityCounts.Low, lastScanData.SeverityCounts.Low)
			assert.Equal(t, tc.expected.SeverityCounts.None, lastScanData.SeverityCounts.None)
			assert.Equal(t, tc.expected.SeverityCounts.Unknown, lastScanData.SeverityCounts.Unknown)

			assert.Equal(t, tc.expected.ScanDate, lastScanData.ScanDate)
		})
	}
}

func TestTenantService_GetHostsVulnerabilityTrends(t *testing.T) {
	testCases := []struct {
		name      string // description of this test case
		mockSetup func(mockStore *mocks.MockStorage)
		// Named input parameters for target function.
		hostIDs          []int
		timePeriodFilter domain.TimePeriodFilter
		severityFilters  []string
		want             []domain.ServiceTimePeriod
		wantErr          bool
	}{
		{
			name: "Two hosts with no timePeriodFilter and no severityFilters",
			mockSetup: func(mockStore *mocks.MockStorage) {
				mockStore.MockGetHostVulnerabilityTrends = func(hostID int, timePeriodFilter string, severityFilters []string) ([]domain.ServiceTimePeriod, error) {
					return []domain.ServiceTimePeriod{
						{TimePeriod: "January", VulnerabilityCount: 5},
						{TimePeriod: "February", VulnerabilityCount: 10},
						{TimePeriod: "March", VulnerabilityCount: 0},
						{TimePeriod: "April", VulnerabilityCount: 0},
						{TimePeriod: "May", VulnerabilityCount: 0},
						{TimePeriod: "June", VulnerabilityCount: 0},
						{TimePeriod: "July", VulnerabilityCount: 0},
						{TimePeriod: "Agust", VulnerabilityCount: 0},
						{TimePeriod: "September", VulnerabilityCount: 0},
						{TimePeriod: "October", VulnerabilityCount: 0},
						{TimePeriod: "November", VulnerabilityCount: 0},
						{TimePeriod: "December", VulnerabilityCount: 0},
					}, nil
				}
			},
			hostIDs:          []int{1, 2},
			timePeriodFilter: domain.TimePeriodFilterMonth,
			severityFilters:  []string{},
			want: []domain.ServiceTimePeriod{
				{TimePeriod: "January", VulnerabilityCount: 10},
				{TimePeriod: "February", VulnerabilityCount: 20},
				{TimePeriod: "March", VulnerabilityCount: 0},
				{TimePeriod: "April", VulnerabilityCount: 0},
				{TimePeriod: "May", VulnerabilityCount: 0},
				{TimePeriod: "June", VulnerabilityCount: 0},
				{TimePeriod: "July", VulnerabilityCount: 0},
				{TimePeriod: "August", VulnerabilityCount: 0},
				{TimePeriod: "September", VulnerabilityCount: 0},
				{TimePeriod: "October", VulnerabilityCount: 0},
				{TimePeriod: "November", VulnerabilityCount: 0},
				{TimePeriod: "December", VulnerabilityCount: 0},
			},
			wantErr: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockStore := &mocks.MockStorage{}
			tc.mockSetup(mockStore)

			s := NewTenantService(mockStore)
			got, gotErr := s.GetHostsVulnerabilityTrends(tc.hostIDs, tc.timePeriodFilter, tc.severityFilters)
			if gotErr != nil {
				if !tc.wantErr {
					assert.NoError(t, gotErr)
				}
				return
			}
			if tc.wantErr {
				assert.Error(t, gotErr)
			}

			assert.Equal(t, len(tc.want), len(got))
			for i, wantPeriod := range tc.want {
				assert.Equal(t, wantPeriod.TimePeriod, got[i].TimePeriod)
				assert.Equal(t, wantPeriod.VulnerabilityCount, got[i].VulnerabilityCount)
			}
		})
	}
}

package services

import (
	"fmt"
	"sort"
	"testing"

	"github.com/google/uuid"
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

			fmt.Printf("Got aliasVulnerPairs: %+v\n", aliasVulnerPairs)

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

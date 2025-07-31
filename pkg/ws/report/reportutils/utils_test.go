package reportutils_test

import (
	"sort"
	"testing"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
	"github.com/stretchr/testify/assert"
)

func TestBuildVulnerabilityTypeData(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns []tools.Vulnerability
		want  dto.InitialDataResponse
	}{
		{
			name:  "Nil vulnerabilities",
			vulns: nil,
			want: dto.InitialDataResponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.OwaspCategorySSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInjection.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 0,
				GlobalCVSSScore:            0.0,
			},
		},
		{
			name:  "Empty vulnerabilities",
			vulns: []tools.Vulnerability{},
			want: dto.InitialDataResponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.OwaspCategorySSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInjection.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 0,
				GlobalCVSSScore:            0.0,
			},
		},
		{
			name: "Multiple Vulnerabilities of same type",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 7.5},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 8.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 7.5},
			},
			want: dto.InitialDataResponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.OwaspCategorySSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInjection.String(), HighestCvss: 8.0, Count: 3, Percentage: 1, AvailableCvssValues: []float64{0.0, 7.5, 8.0}},
					{Name: enums.OwaspCategoryVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 3,
				GlobalCVSSScore:            8.0,
			},
		},
		{
			name: "Multiple Vulnerabilities of different type",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 7.5},
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 9.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 7.5},
			},
			want: dto.InitialDataResponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.OwaspCategorySSRF.String(), HighestCvss: 9.0, Count: 1, Percentage: 0.3333333333333333, AvailableCvssValues: []float64{0.0, 9.0}},
					{Name: enums.OwaspCategorySoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInjection.String(), HighestCvss: 7.5, Count: 2, Percentage: 0.6666666666666666, AvailableCvssValues: []float64{0.0, 7.5}},
					{Name: enums.OwaspCategoryVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 3,
				GlobalCVSSScore:            9.0,
			},
		},
		{
			name: "Vulnerabilities with unknown category",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategory("UnknownCategory"), BaseCVSSScore: 7.5}, // Unknown category - should be skipped
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 6.0},
			},
			want: dto.InitialDataResponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					// Should only include the standard OWASP categories
					{Name: enums.OwaspCategorySSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInjection.String(), HighestCvss: 6.0, Count: 1, Percentage: 1.0, AvailableCvssValues: []float64{0.0, 6.0}},
					{Name: enums.OwaspCategoryVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					// Unknown category is NOT included - skipped and logged as warning
				},
				GlobalTotalVulnerabilities: 1,   // Only the valid vulnerability is counted
				GlobalCVSSScore:            6.0, // Global CVSS from the valid vulnerability only
			},
		},
		{
			name: "Vulnerabilities with zero CVSS",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 0.0},
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 0.0},
			},
			want: dto.InitialDataResponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.OwaspCategorySSRF.String(), HighestCvss: 0.0, Count: 1, Percentage: 0.5, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInjection.String(), HighestCvss: 0.0, Count: 1, Percentage: 0.5, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategorySecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.OwaspCategoryNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 2,
				GlobalCVSSScore:            0.0,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.BuildVulnerabilityTypeData(tc.vulns)

			sort.Slice(got.VulnerabilityTypes, func(i, j int) bool {
				return got.VulnerabilityTypes[i].Name < got.VulnerabilityTypes[j].Name
			})

			sort.Slice(tc.want.VulnerabilityTypes, func(i, j int) bool {
				return tc.want.VulnerabilityTypes[i].Name < tc.want.VulnerabilityTypes[j].Name
			})

			assert.Equal(t, len(tc.want.VulnerabilityTypes), len(got.VulnerabilityTypes))
			assert.Equal(t, tc.want.GlobalCVSSScore, got.GlobalCVSSScore)
			assert.Equal(t, tc.want.GlobalTotalVulnerabilities, got.GlobalTotalVulnerabilities)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetMaxCVSSPerType(t *testing.T) {
	testCases := []struct {
		name  string
		vulns []tools.Vulnerability
		want  map[enums.OwaspCategory]float64
	}{
		{
			name:  "Nil vulnerabilities",
			vulns: nil,
			want: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:                                    0.0,
				enums.OwaspCategorySoftwareAndDataIntegrityFailures:        0.0,
				enums.OwaspCategoryCryptographicFailures:                   0.0,
				enums.OwaspCategoryIdentificationAndAuthenticationFailures: 0.0,
				enums.OwaspCategoryBrokenAccessControl:                     0.0,
				enums.OwaspCategorySecurityLoggingAndMonitoringFailures:    0.0,
				enums.OwaspCategoryInjection:                               0.0,
				enums.OwaspCategoryVulnerableAndOutdatedComponents:         0.0,
				enums.OwaspCategoryInsecureDesign:                          0.0,
				enums.OwaspCategorySecurityMisconfiguration:                0.0,
				enums.OwaspCategoryOther:                                   0.0,
				enums.OwaspCategoryNoInfo:                                  0.0,
			},
		},
		{
			name:  "Empty vulnerabilities",
			vulns: []tools.Vulnerability{},
			want: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:                                    0.0,
				enums.OwaspCategorySoftwareAndDataIntegrityFailures:        0.0,
				enums.OwaspCategoryCryptographicFailures:                   0.0,
				enums.OwaspCategoryIdentificationAndAuthenticationFailures: 0.0,
				enums.OwaspCategoryBrokenAccessControl:                     0.0,
				enums.OwaspCategorySecurityLoggingAndMonitoringFailures:    0.0,
				enums.OwaspCategoryInjection:                               0.0,
				enums.OwaspCategoryVulnerableAndOutdatedComponents:         0.0,
				enums.OwaspCategoryInsecureDesign:                          0.0,
				enums.OwaspCategorySecurityMisconfiguration:                0.0,
				enums.OwaspCategoryOther:                                   0.0,
				enums.OwaspCategoryNoInfo:                                  0.0,
			},
		},
		{
			name: "Multiple vulnerabilities with different types and scores",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 7.5},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 8.0},
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 6.5},
			},
			want: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:                                    6.5,
				enums.OwaspCategorySoftwareAndDataIntegrityFailures:        0.0,
				enums.OwaspCategoryCryptographicFailures:                   0.0,
				enums.OwaspCategoryIdentificationAndAuthenticationFailures: 0.0,
				enums.OwaspCategoryBrokenAccessControl:                     0.0,
				enums.OwaspCategorySecurityLoggingAndMonitoringFailures:    0.0,
				enums.OwaspCategoryInjection:                               8.0,
				enums.OwaspCategoryVulnerableAndOutdatedComponents:         0.0,
				enums.OwaspCategoryInsecureDesign:                          0.0,
				enums.OwaspCategorySecurityMisconfiguration:                0.0,
				enums.OwaspCategoryOther:                                   0.0,
				enums.OwaspCategoryNoInfo:                                  0.0,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.GetMaxCVSSPerType(tc.vulns)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_GetGlobalCVSSScore(t *testing.T) {
	testCases := []struct {
		name  string
		vulns []tools.Vulnerability
		want  float64
	}{
		{
			name:  "Empty Vulnerabilities",
			vulns: []tools.Vulnerability{},
			want:  0.0,
		},
		{
			name: "Single vulnerability",
			vulns: []tools.Vulnerability{
				{BaseCVSSScore: 7.5},
			},
			want: 7.5,
		},
		{
			name: "Multiple Vulnerabilities",
			vulns: []tools.Vulnerability{
				{BaseCVSSScore: 7.5},
				{BaseCVSSScore: 1.5},
				{BaseCVSSScore: 2.5},
			},
			want: 7.5,
		},
		{
			name: "Vulnerability with cero CVSS",
			vulns: []tools.Vulnerability{
				{BaseCVSSScore: 0.0},
				{BaseCVSSScore: 1.5},
				{BaseCVSSScore: 2.5},
			},
			want: 2.5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.GetGlobalCVSSScore(tc.vulns)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilterVulnerabilitiesByStatus(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns         []tools.Vulnerability
		status        map[enums.OwaspCategory]float64
		wantSolved    []tools.Vulnerability
		wantNotSolved []tools.Vulnerability
	}{
		{
			name:          "Empty vulnerability slice",
			vulns:         []tools.Vulnerability{},
			status:        map[enums.OwaspCategory]float64{},
			wantSolved:    []tools.Vulnerability{},
			wantNotSolved: []tools.Vulnerability{},
		},
		{
			name: "Vulnerability slice with empty status",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF},
				{Type: enums.OwaspCategoryInjection},
			},
			status:     map[enums.OwaspCategory]float64{},
			wantSolved: []tools.Vulnerability{},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF},
				{Type: enums.OwaspCategoryInjection},
			},
		},
		{
			name: "Vulnerability slice with non-empty status",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
			status: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:      6.5,
				enums.OwaspCategoryInjection: 4.0,
			},
			wantSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
			},
		},
		{
			name: "Vulnerability slice with status equal to the CVSS",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
			status: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:      5.0,
				enums.OwaspCategoryInjection: 5.0,
			},
			wantSolved: []tools.Vulnerability{},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
		},
		{
			name: "Status with 0.0 Desired CVSS",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
			status: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:      0.0,
				enums.OwaspCategoryInjection: 0.0,
			},
			wantSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
			wantNotSolved: []tools.Vulnerability{},
		},
		{
			name: "Vulnerability with Type not included in map",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryOther, BaseCVSSScore: 5.0},
			},
			status: map[enums.OwaspCategory]float64{
				enums.OwaspCategorySSRF:      0.0,
				enums.OwaspCategoryInjection: 0.0,
			},
			wantSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategorySSRF, BaseCVSSScore: 5.0},
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 5.0},
			},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.OwaspCategoryOther, BaseCVSSScore: 5.0},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotSolved, gotNotSolved := reportutils.FilterVulnerabilitiesByStatus(tc.vulns, tc.status)

			assert.Equal(t, gotSolved, tc.wantSolved, "FilterVulnerabilitiesByStatus() = %v, want %v", gotSolved, tc.wantSolved)
			assert.Equal(t, gotNotSolved, tc.wantNotSolved, "FilterVulnerabilitiesByStatus() = %v, want %v", gotNotSolved, tc.wantNotSolved)
		})
	}
}

func TestGetHighestCVSSVulnerabilityOfType(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns    []tools.Vulnerability
		vulnType enums.OwaspCategory
		want     *tools.Vulnerability
	}{
		{
			name: "One vulnerability of type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.5,
				},
			},
			vulnType: enums.OwaspCategoryInjection,
			want: &tools.Vulnerability{
				Type:          enums.OwaspCategoryInjection,
				BaseCVSSScore: 5.5,
			},
		},
		{
			name: "One vulnerability but not of type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.5,
				},
			},
			vulnType: enums.OwaspCategoryBrokenAccessControl,
			want:     nil,
		},
		{
			name: "Multiple vulnerabilities of different type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.5,
				},
				{
					Type:          enums.OwaspCategorySSRF,
					BaseCVSSScore: 5.6,
				},
			},
			vulnType: enums.OwaspCategoryInjection,
			want: &tools.Vulnerability{
				Type:          enums.OwaspCategoryInjection,
				BaseCVSSScore: 5.5,
			},
		},
		{
			name: "Multiple vulnerabilities of same type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.5,
				},
				{
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.6,
				},
			},
			vulnType: enums.OwaspCategoryInjection,
			want: &tools.Vulnerability{
				Type:          enums.OwaspCategoryInjection,
				BaseCVSSScore: 5.6,
			},
		},
		{
			name: "Multiple vulnerabilities of same type and CVSS",
			vulns: []tools.Vulnerability{
				{
					CveID:         "CVE-2024",
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.5,
				},
				{
					CveID:         "CVE-2012",
					Type:          enums.OwaspCategoryInjection,
					BaseCVSSScore: 5.5,
				},
			},
			vulnType: enums.OwaspCategoryInjection,
			want: &tools.Vulnerability{
				CveID:         "CVE-2024",
				Type:          enums.OwaspCategoryInjection,
				BaseCVSSScore: 5.5,
			},
		},
		{
			name:     "Empty vulnerabilities",
			vulns:    []tools.Vulnerability{},
			vulnType: enums.OwaspCategoryInjection,
			want:     nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.GetHighestCVSSVulnerabilityOfType(tc.vulns, tc.vulnType)

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetUniqueVulnTypes(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns []tools.Vulnerability
		want  []enums.OwaspCategory
	}{
		{
			name: "Slice with one vulnerability type",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection},
			},
			want: []enums.OwaspCategory{enums.OwaspCategoryInjection},
		},
		{
			name:  "Empty vulnerability slice",
			vulns: []tools.Vulnerability{},
			want:  []enums.OwaspCategory{},
		},
		{
			name: "Slice with two vulnerabilities with the same type",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection},
				{Type: enums.OwaspCategoryInjection},
			},
			want: []enums.OwaspCategory{enums.OwaspCategoryInjection},
		},
		{
			name: "Slice with two vulnerabilities with a different type",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection},
				{Type: enums.OwaspCategorySSRF},
			},
			want: []enums.OwaspCategory{
				enums.OwaspCategoryInjection, enums.OwaspCategorySSRF,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.GetUniqueVulnTypes(tc.vulns)

			assert.Equal(t, tc.want, got, "Expected weakness type slice %v, got %v", tc.want, got)
		})
	}
}

func TestBuildVulnerabilityGraph(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns          []tools.Vulnerability
		notSolvedVulns []tools.Vulnerability
		want           dto.GraphData
	}{
		{
			name: "One unsolved vuln",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 6.6},
			},
			notSolvedVulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 6.6},
			},
			want: dto.GraphData{
				Series: []dto.Series{
					{Name: "Actual", Data: []dto.DataPoint{{X: enums.OwaspCategoryInjection.String(), Y: 6.6}}, Average: 6.6},
					{Name: "Expected", Data: []dto.DataPoint{{X: enums.OwaspCategoryInjection.String(), Y: 6.6}}, Average: 6.6},
				},
			},
		},
		{
			name:           "Empty vulns",
			vulns:          []tools.Vulnerability{},
			notSolvedVulns: []tools.Vulnerability{},
			want: dto.GraphData{
				Series: []dto.Series{
					{Name: "Actual", Data: []dto.DataPoint{}, Average: 0.0},
					{Name: "Expected", Data: []dto.DataPoint{}, Average: 0.0},
				},
			},
		},
		{
			name: "No unsolved vulns",
			vulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 6.6},
			},
			notSolvedVulns: []tools.Vulnerability{},
			want: dto.GraphData{
				Series: []dto.Series{
					{Name: "Actual", Data: []dto.DataPoint{{X: enums.OwaspCategoryInjection.String(), Y: 6.6}}, Average: 6.6},
					{Name: "Expected", Data: []dto.DataPoint{{X: enums.OwaspCategoryInjection.String(), Y: 0.0}}, Average: 0.0},
				},
			},
		},
		{
			name:  "No vulns but one unsolved vuln",
			vulns: []tools.Vulnerability{},
			notSolvedVulns: []tools.Vulnerability{
				{Type: enums.OwaspCategoryInjection, BaseCVSSScore: 6.6},
			},
			want: dto.GraphData{
				Series: []dto.Series{
					{Name: "Actual", Data: []dto.DataPoint{}, Average: 0.0},
					{Name: "Expected", Data: []dto.DataPoint{}, Average: 0.0},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.BuildVulnerabilityGraph(tc.vulns, tc.notSolvedVulns)

			assert.Equal(t, tc.want, got, "Expected GraphData %v, got %v", tc.want, got)
		})
	}
}

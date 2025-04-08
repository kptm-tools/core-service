package reportutils_test

import (
	"testing"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/ws/report/dto"
	"github.com/kptm-tools/core-service/pkg/ws/report/reportutils"
	"github.com/stretchr/testify/assert"
)

func TestBuildVulnerabilityTypeData(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns []*domain.Vulnerability
		want  dto.InitialDataReponse
	}{
		{
			name:  "Empty vulnerabilities",
			vulns: []*domain.Vulnerability{},
			want: dto.InitialDataReponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 0,
				GlobalCVSSScore:            0.0,
			},
		},
		{
			name: "Multiple Vulnerabilities of same type",
			vulns: []*domain.Vulnerability{
				{Type: enums.WeaknessInjection.String(), BaseCVSSScore: 7.5},
				{Type: enums.WeaknessInjection.String(), BaseCVSSScore: 8.0},
				{Type: enums.WeaknessInjection.String(), BaseCVSSScore: 7.5},
			},
			want: dto.InitialDataReponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 8.0, Count: 3, Percentage: 1, AvailableCvssValues: []float64{0.0, 7.5, 8.0}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 3,
				GlobalCVSSScore:            8.0,
			},
		},
		{
			name: "Multiple Vulnerabilities of different type",
			vulns: []*domain.Vulnerability{
				{Type: enums.WeaknessInjection.String(), BaseCVSSScore: 7.5},
				{Type: enums.WeaknessSSRF.String(), BaseCVSSScore: 9.0},
				{Type: enums.WeaknessInjection.String(), BaseCVSSScore: 7.5},
			},
			want: dto.InitialDataReponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 9.0, Count: 1, Percentage: 0.3333333333333333, AvailableCvssValues: []float64{0.0, 9.0}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 7.5, Count: 2, Percentage: 0.6666666666666666, AvailableCvssValues: []float64{0.0, 7.5}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 3,
				GlobalCVSSScore:            9.0,
			},
		},
		{
			name: "Vulnerabilities with zero CVSS",
			vulns: []*domain.Vulnerability{
				{Type: enums.WeaknessInjection.String(), BaseCVSSScore: 0.0},
				{Type: enums.WeaknessSSRF.String(), BaseCVSSScore: 0.0},
			},
			want: dto.InitialDataReponse{
				VulnerabilityTypes: []dto.VulnerabilityTypeData{
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 0.0, Count: 1, Percentage: 0.5, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 0.0, Count: 1, Percentage: 0.5, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{0.0}},
				},
				GlobalTotalVulnerabilities: 2,
				GlobalCVSSScore:            0.0,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.BuildVulnerabilityTypeData(tc.vulns)

			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_GetGlobalCVSSScore(t *testing.T) {
	testCases := []struct {
		name  string
		vulns []*domain.Vulnerability
		want  float64
	}{
		{
			name:  "Empty Vulnerabilities",
			vulns: []*domain.Vulnerability{},
			want:  0.0,
		},
		{
			name: "Single vulnerability",
			vulns: []*domain.Vulnerability{
				{BaseCVSSScore: 7.5},
			},
			want: 7.5,
		},
		{
			name: "Multiple Vulnerabilities",
			vulns: []*domain.Vulnerability{
				{BaseCVSSScore: 7.5},
				{BaseCVSSScore: 1.5},
				{BaseCVSSScore: 2.5},
			},
			want: 7.5,
		},
		{
			name: "Vulnerability with cero CVSS",
			vulns: []*domain.Vulnerability{
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

func TestGetUniqueCVSSValuesPerType(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns []*domain.Vulnerability
		want  reportutils.UniqueCVSSValuesByType
	}{
		{
			name:  "Empty Vulnerabilities",
			vulns: []*domain.Vulnerability{},
			want: reportutils.UniqueCVSSValuesByType{
				enums.WeaknessSSRF: map[float64]bool{0.0: true},
				enums.WeaknessSoftwareAndDataIntegrityFailures:        map[float64]bool{0.0: true},
				enums.WeaknessCryptographicFailures:                   map[float64]bool{0.0: true},
				enums.WeaknessIdentificationAndAuthenticationFailures: map[float64]bool{0.0: true},
				enums.WeaknessBrokenAccessControl:                     map[float64]bool{0.0: true},
				enums.WeaknessSecurityLoggingAndMonitoringFailures:    map[float64]bool{0.0: true},
				enums.WeaknessInjection:                               map[float64]bool{0.0: true},
				enums.WeaknessVulnerableAndOutdatedComponents:         map[float64]bool{0.0: true},
				enums.WeaknessInsecureDesign:                          map[float64]bool{0.0: true},
				enums.WeaknessSecurityMisconfiguration:                map[float64]bool{0.0: true},
				enums.WeaknessOther:                                   map[float64]bool{0.0: true},
				enums.WeaknessNoInfo:                                  map[float64]bool{0.0: true},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportutils.GetUniqueCVSSValuesPerType(tc.vulns)

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFilterVulnerabilitiesByStatus(t *testing.T) {
	testCases := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		vulns         []*domain.Vulnerability
		status        map[string]float64
		wantSolved    []*domain.Vulnerability
		wantNotSolved []*domain.Vulnerability
	}{
		{
			name:          "Empty vulnerability slice",
			vulns:         []*domain.Vulnerability{},
			status:        map[string]float64{},
			wantSolved:    []*domain.Vulnerability{},
			wantNotSolved: []*domain.Vulnerability{},
		},
		{
			name: "Vulnerability slice with empty status",
			vulns: []*domain.Vulnerability{
				{Type: "SSRF"},
				{Type: "Injection"},
			},
			status:     map[string]float64{},
			wantSolved: []*domain.Vulnerability{},
			wantNotSolved: []*domain.Vulnerability{
				{Type: "SSRF"},
				{Type: "Injection"},
			},
		},
		{
			name: "Vulnerability slice with non-empty status",
			vulns: []*domain.Vulnerability{
				{Type: "SSRF", BaseCVSSScore: 5.0},
				{Type: "Injection", BaseCVSSScore: 5.0},
			},
			status: map[string]float64{
				"SSRF":      6.5,
				"Injection": 4.0,
			},
			wantSolved: []*domain.Vulnerability{
				{Type: "Injection", BaseCVSSScore: 5.0},
			},
			wantNotSolved: []*domain.Vulnerability{
				{Type: "SSRF", BaseCVSSScore: 5.0},
			},
		},
		{
			name: "Vulnerability slice with status equal to the CVSS",
			vulns: []*domain.Vulnerability{
				{Type: "SSRF", BaseCVSSScore: 5.0},
				{Type: "Injection", BaseCVSSScore: 5.0},
			},
			status: map[string]float64{
				"SSRF":      5.0,
				"Injection": 5.0,
			},
			wantSolved: []*domain.Vulnerability{},
			wantNotSolved: []*domain.Vulnerability{
				{Type: "SSRF", BaseCVSSScore: 5.0},
				{Type: "Injection", BaseCVSSScore: 5.0},
			},
		},
		{
			name: "Status with 0.0 Desired CVSS",
			vulns: []*domain.Vulnerability{
				{Type: "SSRF", BaseCVSSScore: 5.0},
				{Type: "Injection", BaseCVSSScore: 5.0},
			},
			status: map[string]float64{
				"SSRF":      0.0,
				"Injection": 0.0,
			},
			wantSolved: []*domain.Vulnerability{
				{Type: "SSRF", BaseCVSSScore: 5.0},
				{Type: "Injection", BaseCVSSScore: 5.0},
			},
			wantNotSolved: []*domain.Vulnerability{},
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

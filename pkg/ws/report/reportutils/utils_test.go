package reportutils_test

import (
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
			name:  "Empty vulnerabilities",
			vulns: []tools.Vulnerability{},
			want: dto.InitialDataResponse{
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
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection, BaseCVSSScore: 7.5},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 8.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 7.5},
			},
			want: dto.InitialDataResponse{
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
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection, BaseCVSSScore: 7.5},
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 9.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 7.5},
			},
			want: dto.InitialDataResponse{
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
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection, BaseCVSSScore: 0.0},
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 0.0},
			},
			want: dto.InitialDataResponse{
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
		status        map[enums.WeaknessType]float64
		wantSolved    []tools.Vulnerability
		wantNotSolved []tools.Vulnerability
	}{
		{
			name:          "Empty vulnerability slice",
			vulns:         []tools.Vulnerability{},
			status:        map[enums.WeaknessType]float64{},
			wantSolved:    []tools.Vulnerability{},
			wantNotSolved: []tools.Vulnerability{},
		},
		{
			name: "Vulnerability slice with empty status",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF},
				{Type: enums.WeaknessInjection},
			},
			status:     map[enums.WeaknessType]float64{},
			wantSolved: []tools.Vulnerability{},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF},
				{Type: enums.WeaknessInjection},
			},
		},
		{
			name: "Vulnerability slice with non-empty status",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
			status: map[enums.WeaknessType]float64{
				enums.WeaknessSSRF:      6.5,
				enums.WeaknessInjection: 4.0,
			},
			wantSolved: []tools.Vulnerability{
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
			},
		},
		{
			name: "Vulnerability slice with status equal to the CVSS",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
			status: map[enums.WeaknessType]float64{
				enums.WeaknessSSRF:      5.0,
				enums.WeaknessInjection: 5.0,
			},
			wantSolved: []tools.Vulnerability{},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
		},
		{
			name: "Status with 0.0 Desired CVSS",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
			status: map[enums.WeaknessType]float64{
				enums.WeaknessSSRF:      0.0,
				enums.WeaknessInjection: 0.0,
			},
			wantSolved: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
			wantNotSolved: []tools.Vulnerability{},
		},
		{
			name: "Vulnerability with Type not included in map",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessOther, BaseCVSSScore: 5.0},
			},
			status: map[enums.WeaknessType]float64{
				enums.WeaknessSSRF:      0.0,
				enums.WeaknessInjection: 0.0,
			},
			wantSolved: []tools.Vulnerability{
				{Type: enums.WeaknessSSRF, BaseCVSSScore: 5.0},
				{Type: enums.WeaknessInjection, BaseCVSSScore: 5.0},
			},
			wantNotSolved: []tools.Vulnerability{
				{Type: enums.WeaknessOther, BaseCVSSScore: 5.0},
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
		vulnType enums.WeaknessType
		want     *tools.Vulnerability
	}{
		{
			name: "One vulnerability of type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.5,
				},
			},
			vulnType: enums.WeaknessInjection,
			want: &tools.Vulnerability{
				Type:          enums.WeaknessInjection,
				BaseCVSSScore: 5.5,
			},
		},
		{
			name: "One vulnerability but not of type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.5,
				},
			},
			vulnType: enums.WeaknessBrokenAccessControl,
			want:     nil,
		},
		{
			name: "Multiple vulnerabilities of different type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.5,
				},
				{
					Type:          enums.WeaknessSSRF,
					BaseCVSSScore: 5.6,
				},
			},
			vulnType: enums.WeaknessInjection,
			want: &tools.Vulnerability{
				Type:          enums.WeaknessInjection,
				BaseCVSSScore: 5.5,
			},
		},
		{
			name: "Multiple vulnerabilities of same type",
			vulns: []tools.Vulnerability{
				{
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.5,
				},
				{
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.6,
				},
			},
			vulnType: enums.WeaknessInjection,
			want: &tools.Vulnerability{
				Type:          enums.WeaknessInjection,
				BaseCVSSScore: 5.6,
			},
		},
		{
			name: "Multiple vulnerabilities of same type and CVSS",
			vulns: []tools.Vulnerability{
				{
					CveID:         "CVE-2024",
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.5,
				},
				{
					CveID:         "CVE-2012",
					Type:          enums.WeaknessInjection,
					BaseCVSSScore: 5.5,
				},
			},
			vulnType: enums.WeaknessInjection,
			want: &tools.Vulnerability{
				CveID:         "CVE-2024",
				Type:          enums.WeaknessInjection,
				BaseCVSSScore: 5.5,
			},
		},
		{
			name:     "Empty vulnerabilities",
			vulns:    []tools.Vulnerability{},
			vulnType: enums.WeaknessInjection,
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
		want  []enums.WeaknessType
	}{
		{
			name: "Slice with one vulnerability type",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection},
			},
			want: []enums.WeaknessType{enums.WeaknessInjection},
		},
		{
			name:  "Empty vulnerability slice",
			vulns: []tools.Vulnerability{},
			want:  []enums.WeaknessType{},
		},
		{
			name: "Slice with two vulnerabilities with the same type",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection},
				{Type: enums.WeaknessInjection},
			},
			want: []enums.WeaknessType{enums.WeaknessInjection},
		},
		{
			name: "Slice with two vulnerabilities with a different type",
			vulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection},
				{Type: enums.WeaknessSSRF},
			},
			want: []enums.WeaknessType{
				enums.WeaknessInjection, enums.WeaknessSSRF,
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
				{Type: enums.WeaknessInjection, BaseCVSSScore: 6.6},
			},
			notSolvedVulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection, BaseCVSSScore: 6.6},
			},
			want: dto.GraphData{
				Series: []dto.Series{
					{Name: "Actual", Data: []dto.DataPoint{{X: enums.WeaknessInjection.String(), Y: 6.6}}, Average: 6.6},
					{Name: "Expected", Data: []dto.DataPoint{{X: enums.WeaknessInjection.String(), Y: 6.6}}, Average: 6.6},
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
				{Type: enums.WeaknessInjection, BaseCVSSScore: 6.6},
			},
			notSolvedVulns: []tools.Vulnerability{},
			want: dto.GraphData{
				Series: []dto.Series{
					{Name: "Actual", Data: []dto.DataPoint{{X: enums.WeaknessInjection.String(), Y: 6.6}}, Average: 6.6},
					{Name: "Expected", Data: []dto.DataPoint{{X: enums.WeaknessInjection.String(), Y: 0.0}}, Average: 0.0},
				},
			},
		},
		{
			name:  "No vulns but one unsolved vuln",
			vulns: []tools.Vulnerability{},
			notSolvedVulns: []tools.Vulnerability{
				{Type: enums.WeaknessInjection, BaseCVSSScore: 6.6},
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

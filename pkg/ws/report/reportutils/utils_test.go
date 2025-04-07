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
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
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
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 8.0, Count: 3, Percentage: 1, AvailableCvssValues: []float64{7.5, 8.0}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
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
					{Name: enums.WeaknessSSRF.String(), HighestCvss: 9.0, Count: 1, Percentage: 0.3333333333333333, AvailableCvssValues: []float64{9.0}},
					{Name: enums.WeaknessSoftwareAndDataIntegrityFailures.String(), HighestCvss: 0.0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessCryptographicFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessIdentificationAndAuthenticationFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessBrokenAccessControl.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSecurityLoggingAndMonitoringFailures.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessInjection.String(), HighestCvss: 7.5, Count: 2, Percentage: 0.6666666666666666, AvailableCvssValues: []float64{7.5}},
					{Name: enums.WeaknessVulnerableAndOutdatedComponents.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessInsecureDesign.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessSecurityMisconfiguration.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessOther.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
					{Name: enums.WeaknessNoInfo.String(), HighestCvss: 0, Count: 0, Percentage: 0, AvailableCvssValues: []float64{}},
				},
				GlobalTotalVulnerabilities: 3,
				GlobalCVSSScore:            9.0,
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

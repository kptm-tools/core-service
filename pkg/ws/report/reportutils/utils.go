package reportutils

import (
	"log/slog"
	"sort"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
)

type (
	// MaxCVSSPerType maps each WeaknessType to its maximum observed CVSS score
	MaxCVSSPerType map[enums.WeaknessType]float64
	// vulnerabilityCountByType maps each WeaknessType to the number of vulnerabilities of that type.
	vulnerabilityCountByType map[enums.WeaknessType]int
	// uniqueCVSSValues represents a set of unique CVSS scores.
	uniqueCVSSValues map[float64]bool
	// UniqueCVSSValuesByType maps each WeaknessType to a set of its unique CVSS Scores.
	UniqueCVSSValuesByType map[enums.WeaknessType]uniqueCVSSValues
)

// BuildVulnerabilityTypeData processes a slice of vulnerabilities to calculate and format data for the initial report response.
// It calculates the highest CVSS score, count, percentage, and unique CVSS values for each vulnerability type,
// as well as the global total vulnerabilities and global CVSS score.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects to process.
//
// Returns:
//
//	A dto.InitialDataReponse struct containing the processed vulnerability data.
func BuildVulnerabilityTypeData(vulns []*domain.Vulnerability) dto.InitialDataReponse {
	maxCVSSPerType := make(MaxCVSSPerType)
	vulnCountPerType := make(vulnerabilityCountByType)
	uniqueCVSSValuesPerType := make(UniqueCVSSValuesByType)
	globalTotalVulnerabilities := GetGlobalTotalVulnerabilities(vulns)
	globalCVSSScore := 0.0
	vulnerabilityTypesData := make([]dto.VulnerabilityTypeData, 0)

	// Initialize maps with all possible WeaknessType enums and default values
	for i := enums.WeaknessSSRF; i <= enums.WeaknessNoInfo; i++ {
		maxCVSSPerType[i] = 0.0
		vulnCountPerType[i] = 0
		uniqueCVSSValuesPerType[i] = make(uniqueCVSSValues)
		uniqueCVSSValuesPerType[i][0.0] = true // The user can always opt for 0.0
	}

	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		wt, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type while processing report data", slog.String("vuln_type", vuln.Type))
			continue
		}

		// 1. Increase the vuln count for that type
		vulnCountPerType[wt]++

		// 2. Check for max CVSS score
		if vuln.BaseCVSSScore > maxCVSSPerType[wt] {
			maxCVSSPerType[wt] = vuln.BaseCVSSScore
		}

		// 3. Check for unique CVSS values for that type
		uniqueCVSSValuesPerType[wt][vuln.BaseCVSSScore] = true

		// 4. Check and update GlobalCVSSScore
		if vuln.BaseCVSSScore > globalCVSSScore {
			globalCVSSScore = vuln.BaseCVSSScore
		}
	}

	// Format the reponse data
	for i := enums.WeaknessSSRF; i <= enums.WeaknessNoInfo; i++ {
		count := vulnCountPerType[i]
		percentage := 0.0
		if globalTotalVulnerabilities > 0 {
			percentage = float64(count) / float64(globalTotalVulnerabilities)
		}

		availableCvssValues := make([]float64, 0, len(uniqueCVSSValuesPerType))
		for cvss := range uniqueCVSSValuesPerType[i] {
			availableCvssValues = append(availableCvssValues, cvss)
		}
		sort.Float64s(availableCvssValues)

		vulnerabilityTypesData = append(vulnerabilityTypesData, dto.VulnerabilityTypeData{
			Name:                i.String(),
			HighestCvss:         maxCVSSPerType[i],
			Count:               count,
			Percentage:          percentage,
			AvailableCvssValues: availableCvssValues,
		})
	}

	return dto.InitialDataReponse{
		VulnerabilityTypes:         vulnerabilityTypesData,
		GlobalTotalVulnerabilities: globalTotalVulnerabilities,
		GlobalCVSSScore:            globalCVSSScore,
	}
}

// GetMaxCVSSPerType iterates through a slice of vulnerabilities and returns a map
// where each WeaknessType is associated with the highest CVSS score found for that type.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects to process.
//
// Returns:
//
//	A map where keys are enums.WeaknessType and values are the maximum CVSS score for that type.
func GetMaxCVSSPerType(vulns []*domain.Vulnerability) map[enums.WeaknessType]float64 {
	weaknessMap := make(map[enums.WeaknessType]float64)

	// Initialize the map with all possible WeaknessType enums and default values
	for i := enums.WeaknessSSRF; i <= enums.WeaknessNoInfo; i++ {
		weaknessMap[i] = 0.0
	}

	// Iterate through vulnerabilities and update the map with maximum CVSS values
	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		wt, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type while calculating MaxCVSS per type", slog.String("vuln_type", vuln.Type))
			continue
		}

		currentCVSS := vuln.BaseCVSSScore
		if maxCVSS, exists := weaknessMap[wt]; exists {
			if currentCVSS > maxCVSS {
				weaknessMap[wt] = currentCVSS
			}
		} else {
			weaknessMap[wt] = currentCVSS
		}
	}

	return weaknessMap
}

// GetVulnCountPerType iterates through a slice of vulnerabilities and returns a map
// where each WeaknessType is associated with the total count of vulnerabilities of that type.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects to process.
//
// Returns:
//
//	A map where keys are enums.WeaknessType and values are the count of vulnerabilities for that type.
func GetVulnCountPerType(vulns []*domain.Vulnerability) map[enums.WeaknessType]int {
	weaknessMap := make(map[enums.WeaknessType]int)

	// Initialize the map with all possible WeaknessType enums and 0 values
	for i := enums.WeaknessSSRF; i <= enums.WeaknessNoInfo; i++ {
		weaknessMap[i] = 0
	}

	// Iterate through vulnerabilities and update the map
	for _, vuln := range vulns {
		wt, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type while counting vulnerability types", slog.String("vuln_type", vuln.Type))
			continue
		}
		if _, exists := weaknessMap[wt]; exists {
			weaknessMap[wt]++
		} else {
			slog.Warn("Weakness not found in weakness map while counting vulnerability typs", slog.String("vuln_type", vuln.Type), slog.Any("weakness_map", weaknessMap))
		}
	}

	return weaknessMap
}

// GetGlobalCVSSScore iterates through a slice of vulnerabilities and returns the highest CVSS score found across all vulnerabilities.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects to process.
//
// Returns:
//
//	The highest BaseCVSSScore found in the provided vulnerabilities.
func GetGlobalCVSSScore(vulns []*domain.Vulnerability) float64 {
	maxCVSS := 0.0
	for _, vuln := range vulns {
		if vuln.BaseCVSSScore > maxCVSS {
			maxCVSS = vuln.BaseCVSSScore
		}
	}

	return maxCVSS
}

// GetGlobalTotalVulnerabilities returns the total number of vulnerabilities in the provided slice.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects.
//
// Returns:
//
//	The number of vulnerabilities in the slice.
func GetGlobalTotalVulnerabilities(vulns []*domain.Vulnerability) int {
	return len(vulns)
}

func GetUniqueCVSSValuesPerType(vulns []*domain.Vulnerability) UniqueCVSSValuesByType {
	uniqueWeaknessCVSSValuesMap := make(UniqueCVSSValuesByType)

	// Initialize the map with all possible WeaknessType enums and empty float 64 slices
	for i := enums.WeaknessSSRF; i <= enums.WeaknessNoInfo; i++ {
		uniqueWeaknessCVSSValuesMap[i] = make(uniqueCVSSValues)
		uniqueWeaknessCVSSValuesMap[i][0.0] = true
	}

	// Iterate through vulnerabilities
	// For each type, check if the CVSS value has not yet been assigned in the slice
	for _, vuln := range vulns {
		wt, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type while counting vulnerability types", slog.String("vuln_type", vuln.Type))
			continue
		}
		uniqueWeaknessCVSSValuesMap[wt][vuln.BaseCVSSScore] = true
	}

	return uniqueWeaknessCVSSValuesMap
}

// FilterVulnerabilitiesByStatus filters a slice of vulnerabilities based on a client's current status.
//
// It returns two slices:
//   - solved: A slice containing vulnerabilities that would be considered solved
//     if the provided status was applied. A vulnerability is considered solved if
//     its Type exists in the status map and its BaseCVSSScore is strictly
//     greater than the corresponding CVSS threshold.
//   - notSolved: A slice containing vulnerabilities that would not be considered
//     solved if the provided status were applied. This includes vulnerabilities
//     where either:
//   - Their WeaknessType exists in the status map and their BaseCVSS Score
//     is less than or equal to the corresponding CVSS threshold.
//   - Their WeaknessType does not exist as a key in the status map.
func FilterVulnerabilitiesByStatus(vulns []*domain.Vulnerability, status map[enums.WeaknessType]float64) (
	solved []*domain.Vulnerability,
	notSolved []*domain.Vulnerability,
) {
	solved = make([]*domain.Vulnerability, 0)
	notSolved = make([]*domain.Vulnerability, 0)

	for _, vuln := range vulns {
		vulnTypeStr, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type when filtering vulnerabilities by status, skipping vuln...",
				slog.Int("vuln_id", vuln.ID))
			continue
		}

		if cvssThreshold, ok := status[vulnTypeStr]; ok {
			if vuln.BaseCVSSScore > cvssThreshold {
				solved = append(solved, vuln)
			} else {
				notSolved = append(notSolved, vuln)
			}
		} else {
			notSolved = append(notSolved, vuln)
		}
	}

	return solved, notSolved
}

// GetHighestCVSSVulnerabilityOfType gets the vulnerability with the highest CVSS of a slice of a particular type.
func GetHighestCVSSVulnerabilityOfType(vulns []*domain.Vulnerability, vulnType enums.WeaknessType) *domain.Vulnerability {
	var highestVuln *domain.Vulnerability = nil
	maxCVSS := -1.0
	vulnTypeStr := vulnType.String()

	for _, vuln := range vulns {
		if vuln.Type == vulnTypeStr {
			if vuln.BaseCVSSScore > maxCVSS {
				maxCVSS = vuln.BaseCVSSScore
				highestVuln = vuln
			} else if vuln.BaseCVSSScore == maxCVSS {
				// If CVSS is the same, compare ID's (names) alphabetically
				if vuln.VulnerabilityID > highestVuln.VulnerabilityID {
					highestVuln = vuln
				}
			}
		}
	}

	return highestVuln
}

// GetUniqueVulnTypes returns a slice with unique Weakness Types found within a vulnerability slice.
func GetUniqueVulnTypes(vulns []*domain.Vulnerability) []enums.WeaknessType {
	uniqueTypes := make([]enums.WeaknessType, 0)
	for _, vuln := range vulns {
		wt, ok := enums.ParseWeaknessFromString(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type when building vulnerability graph",
				slog.Int("vuln_id", vuln.ID),
				slog.String("vuln_type", vuln.Type))
			continue
		}
		if !contains(uniqueTypes, wt) {
			uniqueTypes = append(uniqueTypes, wt)
		}
	}

	return uniqueTypes
}

func BuildVulnerabilityGraph(vulns []*domain.Vulnerability, notSolvedVulns []*domain.Vulnerability) dto.GraphData {
	actualDataPoints := make([]dto.DataPoint, 0)

	expectedDataPoints := make([]dto.DataPoint, 0)

	// 1. Get each unique type within vulners (X values)
	uniqueTypes := GetUniqueVulnTypes(vulns)

	for _, wt := range uniqueTypes {
		actualHighestCVSS := 0.0
		expectedHighestCVSS := 0.0

		if highestActualVuln := GetHighestCVSSVulnerabilityOfType(vulns, wt); highestActualVuln != nil {
			actualHighestCVSS = highestActualVuln.BaseCVSSScore
		}
		if highestExpectedVuln := GetHighestCVSSVulnerabilityOfType(notSolvedVulns, wt); highestExpectedVuln != nil {
			expectedHighestCVSS = highestExpectedVuln.BaseCVSSScore
		}

		actualDataPoints = append(actualDataPoints, dto.DataPoint{
			X: wt.String(),
			Y: actualHighestCVSS,
		})
		expectedDataPoints = append(expectedDataPoints, dto.DataPoint{
			X: wt.String(),
			Y: expectedHighestCVSS,
		})
	}

	actualAvg := calculateSeriesAvg(actualDataPoints)
	expectedAvg := calculateSeriesAvg(expectedDataPoints)

	return dto.GraphData{
		Series: []dto.Series{
			{Name: "Actual", Data: actualDataPoints, Average: actualAvg},
			{Name: "Expected", Data: expectedDataPoints, Average: expectedAvg},
		},
	}
}

func calculateSeriesAvg(dataPoints []dto.DataPoint) float64 {
	avg := 0.0
	sum := 0.0

	for _, dataPoint := range dataPoints {
		sum += dataPoint.Y
	}
	if len(dataPoints) != 0 {
		avg = sum / float64(len(dataPoints))
	}
	return avg
}

func contains[T comparable](slice []T, value T) bool {
	for _, item := range slice {
		if value == item {
			return true
		}
	}
	return false
}

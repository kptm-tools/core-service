package reportutils

import (
	"log/slog"
	"slices"
	"sort"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/dto"
)

type (
	// MaxCVSSPerType maps each OwaspCategory to its maximum observed CVSS score
	MaxCVSSPerType map[enums.OwaspCategory]float64
	// vulnerabilityCountByType maps each OwaspCategory to the number of vulnerabilities of that type.
	vulnerabilityCountByType map[enums.OwaspCategory]int
	// uniqueCVSSValues represents a set of unique CVSS scores.
	uniqueCVSSValues map[float64]bool
	// UniqueCVSSValuesByType maps each OwaspCategory to a set of its unique CVSS Scores.
	UniqueCVSSValuesByType map[enums.OwaspCategory]uniqueCVSSValues
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
func BuildVulnerabilityTypeData(vulns []tools.Vulnerability) dto.InitialDataResponse {
	// Handle nil slice
	if vulns == nil {
		vulns = []tools.Vulnerability{}
	}

	maxCVSSPerType := make(MaxCVSSPerType)
	vulnCountPerType := make(vulnerabilityCountByType)
	uniqueCVSSValuesPerType := make(UniqueCVSSValuesByType)
	globalCVSSScore := 0.0
	vulnerabilityTypesData := make([]dto.VulnerabilityTypeData, 0)
	validVulnerabilities := 0 // Track count of valid vulnerabilities only

	// Initialize maps with all possible OwaspCategory enums and default values
	for _, cat := range enums.AllOwaspCategories {
		maxCVSSPerType[cat] = 0.0
		vulnCountPerType[cat] = 0
		uniqueCVSSValuesPerType[cat] = make(uniqueCVSSValues)
		uniqueCVSSValuesPerType[cat][0.0] = true // The user can always opt for 0.0
	}

	for _, vuln := range vulns {
		cat := vuln.Type

		// Map unknown categories to the appropriate OWASP category
		// If not in AllOwaspCategories, it should be mapped to OWASP_OTHER or NONE
		if _, exists := maxCVSSPerType[cat]; !exists {
			// This category is not in AllOwaspCategories, so we need to map it
			// According to requirements:
			// - If CWE isn't mapped to OWASP enum -> OWASP_OTHER
			// - If vuln has no CWE ID or CWE None -> NONE
			// For now, we'll default to mapping unknown categories to the existing categories
			// The proper mapping should be done at the vulnerability ingestion level
			slog.Warn("Found vulnerability with unmapped OWASP category, skipping",
				slog.String("category", cat.String()),
				slog.String("cve_id", vuln.CveID))
			continue
		}

		// 1. Increase the vuln count for that type
		vulnCountPerType[cat]++
		validVulnerabilities++

		// 2. Check for max CVSS score
		if vuln.BaseCVSSScore > maxCVSSPerType[cat] {
			maxCVSSPerType[cat] = vuln.BaseCVSSScore
		}

		// 3. Check for unique CVSS values for that type
		uniqueCVSSValuesPerType[cat][vuln.BaseCVSSScore] = true

		// 4. Check and update GlobalCVSSScore
		if vuln.BaseCVSSScore > globalCVSSScore {
			globalCVSSScore = vuln.BaseCVSSScore
		}
	}

	// Only use the predefined OWASP categories - no additional ones
	// Format the response data for all predefined OWASP categories
	for _, cat := range enums.AllOwaspCategories {
		count := vulnCountPerType[cat]
		percentage := 0.0
		if validVulnerabilities > 0 {
			percentage = float64(count) / float64(validVulnerabilities)
		}

		availableCvssValues := make([]float64, 0)
		if uniqueValues, exists := uniqueCVSSValuesPerType[cat]; exists {
			for cvss := range uniqueValues {
				availableCvssValues = append(availableCvssValues, cvss)
			}
		} else {
			// If no unique values exist, at least include 0.0
			availableCvssValues = append(availableCvssValues, 0.0)
		}
		sort.Float64s(availableCvssValues)

		vulnerabilityTypesData = append(vulnerabilityTypesData, dto.VulnerabilityTypeData{
			Name:                cat.String(),
			HighestCvss:         maxCVSSPerType[cat],
			Count:               count,
			Percentage:          percentage,
			AvailableCvssValues: availableCvssValues,
		})
	}

	return dto.InitialDataResponse{
		VulnerabilityTypes:         vulnerabilityTypesData,
		GlobalTotalVulnerabilities: validVulnerabilities,
		GlobalCVSSScore:            globalCVSSScore,
	}
}

// GetMaxCVSSPerType iterates through a slice of vulnerabilities and returns a map
// where each OwaspCategory is associated with the highest CVSS score found for that type.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects to process.
//
// Returns:
//
//	A map where keys are enums.OwaspCategory and values are the maximum CVSS score for that type.
func GetMaxCVSSPerType(vulns []tools.Vulnerability) map[enums.OwaspCategory]float64 {
	categoryMap := make(map[enums.OwaspCategory]float64)

	// Initialize the map with all possible OwaspCategory enums and default values
	for _, cat := range enums.AllOwaspCategories {
		categoryMap[cat] = 0.0
	}

	// Handle nil slice
	if vulns == nil {
		return categoryMap
	}

	// Iterate through vulnerabilities and update the map with maximum CVSS values
	for _, vuln := range vulns {
		cat := vuln.Type

		currentCVSS := vuln.BaseCVSSScore
		if maxCVSS, exists := categoryMap[cat]; exists {
			if currentCVSS > maxCVSS {
				categoryMap[cat] = currentCVSS
			}
		} else {
			categoryMap[cat] = currentCVSS
		}
	}

	return categoryMap
}

// GetVulnCountPerType iterates through a slice of vulnerabilities and returns a map
// where each OwaspCategory is associated with the total count of vulnerabilities of that type.
//
// Parameters:
//
//	vulns: A slice of domain.Vulnerability objects to process.
//
// Returns:
//
//	A map where keys are enums.OwaspCategory and values are the count of vulnerabilities for that type.
func GetVulnCountPerType(vulns []*domain.Vulnerability) map[enums.OwaspCategory]int {
	categoryMap := make(map[enums.OwaspCategory]int)

	// Initialize the map with all possible OwaspCategory enums and 0 values
	for _, cat := range enums.AllOwaspCategories {
		categoryMap[cat] = 0
	}

	// Iterate through vulnerabilities and update the map
	for _, vuln := range vulns {
		wt, ok := enums.ParseOwaspCategory(vuln.Type)
		if !ok {
			slog.Warn("Found an invalid vulnerability type while counting vulnerability types", slog.String("vuln_type", vuln.Type))
			continue
		}
		if _, exists := categoryMap[wt]; exists {
			categoryMap[wt]++
		} else {
			slog.Warn("Category not found in category map while counting vulnerability typs", slog.String("vuln_type", vuln.Type), slog.Any("category_map", categoryMap))
		}
	}

	return categoryMap
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
func GetGlobalCVSSScore(vulns []tools.Vulnerability) float64 {
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
func GetGlobalTotalVulnerabilities(vulns []tools.Vulnerability) int {
	return len(vulns)
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
//   - Their OwaspCategory exists in the status map and their BaseCVSS Score
//     is less than or equal to the corresponding CVSS threshold.
//   - Their OwaspCategory does not exist as a key in the status map.
func FilterVulnerabilitiesByStatus(vulns []tools.Vulnerability, status map[enums.OwaspCategory]float64) (
	solved []tools.Vulnerability,
	notSolved []tools.Vulnerability,
) {
	solved = make([]tools.Vulnerability, 0)
	notSolved = make([]tools.Vulnerability, 0)

	for _, vuln := range vulns {
		cat := vuln.Type

		if cvssThreshold, ok := status[cat]; ok {
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
func GetHighestCVSSVulnerabilityOfType(vulns []tools.Vulnerability, vulnType enums.OwaspCategory) *tools.Vulnerability {
	var highestVuln *tools.Vulnerability
	maxCVSS := -1.0

	for _, vuln := range vulns {
		if vuln.Type == vulnType {
			if vuln.BaseCVSSScore > maxCVSS {
				maxCVSS = vuln.BaseCVSSScore
				v := vuln // Create a copy to avoid loop variable issues
				highestVuln = &v
			} else if vuln.BaseCVSSScore == maxCVSS && highestVuln != nil {
				// If CVSS is the same, compare ID's (names) alphabetically
				if vuln.CveID > highestVuln.CveID {
					highestVuln = &vuln
				}
			}
		}
	}

	return highestVuln
}

// GetUniqueVulnTypes returns a slice with unique Owasp Categories found within a vulnerability slice.
func GetUniqueVulnTypes(vulns []tools.Vulnerability) []enums.OwaspCategory {
	uniqueTypes := []enums.OwaspCategory{}
	for _, vuln := range vulns {
		cat := vuln.Type
		if !slices.Contains(uniqueTypes, cat) {
			uniqueTypes = append(uniqueTypes, cat)
		}
	}

	return uniqueTypes
}

func BuildVulnerabilityGraph(vulns []tools.Vulnerability, notSolvedVulns []tools.Vulnerability) dto.GraphData {
	actualDataPoints := make([]dto.DataPoint, 0)

	expectedDataPoints := make([]dto.DataPoint, 0)

	// 1. Get each unique type within vulners (X values)
	uniqueTypes := GetUniqueVulnTypes(vulns)

	for _, wt := range uniqueTypes {
		actualHighestCVSS := 0.0
		expectedHighestCVSS := 0.0

		highestActualVuln := GetHighestCVSSVulnerabilityOfType(vulns, wt)
		if highestActualVuln != nil {
			actualHighestCVSS = highestActualVuln.BaseCVSSScore
		}

		highestExpectedVuln := GetHighestCVSSVulnerabilityOfType(notSolvedVulns, wt)
		if highestExpectedVuln != nil {
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

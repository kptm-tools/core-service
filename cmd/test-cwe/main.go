// Test utility for validating CWE JSON parsing
// This is a standalone test that validates the CWE parsing logic without requiring database setup.
// Usage: go run test_cwe_parsing.go
//
// This tool is useful for:
// - Validating that data/cwe.json is valid and parseable
// - Debugging CWE parsing issues during development
// - Understanding the structure of parsed CWE data
// - Quick testing after updating the CWE JSON file
package main

import (
	"fmt"
	"log"

	"github.com/kptm-tools/core-service/pkg/services"
)

func main() {
	fmt.Println("CWE Parsing Validation Tool")
	fmt.Println("===========================")
	
	parser := services.NewCWEParser()
	
	// Test parsing the CWE JSON file
	fmt.Println("Loading and parsing data/cwe.json...")
	cweData, err := parser.LoadCWE("data/cwe.json")
	if err != nil {
		log.Fatalf("❌ Failed to parse CWE data: %v", err)
	}
	
	fmt.Printf("✅ Successfully parsed %d CWE weaknesses\n", len(cweData))
	
	// Count weaknesses with mitigations
	withMitigations := 0
	totalMitigations := 0
	for _, weakness := range cweData {
		if len(weakness.Mitigations) > 0 {
			withMitigations++
			totalMitigations += len(weakness.Mitigations)
		}
	}
	
	fmt.Printf("📊 Statistics:\n")
	fmt.Printf("   - Weaknesses with mitigations: %d (%.1f%%)\n", withMitigations, float64(withMitigations)/float64(len(cweData))*100)
	fmt.Printf("   - Total mitigatations: %d\n", totalMitigations)
	fmt.Printf("   - Average mitigations per weakness: %.1f\n", float64(totalMitigations)/float64(len(cweData)))
	
	// Show a few examples with mitigations
	fmt.Printf("\n📝 Sample weaknesses:\n")
	count := 0
	for cweID, weakness := range cweData {
		if count >= 3 {
			break
		}
		// Show examples that have mitigations for more interesting output
		if len(weakness.Mitigations) > 0 {
			fmt.Printf("\n🔍 %s: %s\n", cweID, weakness.Name)
			fmt.Printf("   Description: %s...\n", truncateString(weakness.Description, 100))
			fmt.Printf("   Mitigations: %d\n", len(weakness.Mitigations))
			fmt.Printf("   Last Updated: %s\n", weakness.LastUpdated.Format("2006-01-02"))
			
			// Show first mitigation as example
			if len(weakness.Mitigations) > 0 {
				m := weakness.Mitigations[0]
				fmt.Printf("   Sample Mitigation: [%s] %s\n", m.Phase, truncateString(m.Description, 80))
			}
			count++
		}
	}
	
	fmt.Println("\n✅ CWE parsing validation completed successfully!")
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
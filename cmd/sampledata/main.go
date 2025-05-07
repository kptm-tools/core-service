package main

import (
	"fmt"
	"github.com/brianvoe/gofakeit/v7"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/core-service/cmd/migrations"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/samples"
	"github.com/kptm-tools/core-service/pkg/storage"
)

func Run() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [populate|clear]")
		return
	}

	c := config.LoadConfig()
	coreStore, err := storage.NewPostgreSQLStore(c, migrations.Migrations)
	if err != nil {
		panic(err)
	}

	command := os.Args[1]
	switch command {

	case "populate":
		populateDB(coreStore)
	case "clear":
		fmt.Println("Clearing DB...")
		if err := coreStore.ClearCoreDB(); err != nil {
			panic(err)
		}
		fmt.Println("DB cleared")
	default:
		fmt.Printf("Unknown command `%s`\n", command)
		fmt.Println("Usage: go run main.go [populate|clear]")
	}
}

func populateDB(store interfaces.IStorage) {
	fmt.Println("Populating DB with sample data...")

	tenants, err := populateTenants(store)
	if err != nil {
		panic(err)
	}
	fmt.Println("Tenants populated successfully")

	hosts, errHost := populateHosts(store, tenants)
	if errHost != nil {
		panic(errHost)
	}
	fmt.Println("Hosts populated successfully")

	if err := populateScans(store, tenants, len(hosts)); err != nil {
		panic(err)
	}
	fmt.Println("Scans populated successfully")

	// if err := populateScanResults(store); err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Scan results populated successfully")
}

func populateTenants(store interfaces.IStorage) ([]domain.Tenant, error) {
	sampleTenants := samples.SampleTenants()

	for _, tenant := range sampleTenants {
		_, err := store.CreateTenant(&tenant)
		if err != nil {
			return nil, fmt.Errorf("error populating tenant %s: %w", tenant.ID, err)
		}
	}
	return sampleTenants, nil
}

func populateHosts(store interfaces.IStorage, tenants []domain.Tenant) ([]domain.Host, error) {
	sampleHosts := samples.SampleHosts(10, tenants)

	for _, host := range sampleHosts {
		_, err := store.CreateHost(&host)
		if err != nil {
			return nil, fmt.Errorf("error populating host %s: %w", host.Name, err)
		}
	}
	return sampleHosts, nil
}

func populateScans(store interfaces.IStorage, tenants []domain.Tenant, hostSize int) error {
	sampleScans := samples.SampleScans(10, tenants, hostSize)

	for i, scan := range sampleScans {
		createdScan, err := store.CreateScan(&scan)
		if err != nil {
			return fmt.Errorf("error populating scans: %w", err)
		}
		sampleScans[i] = *createdScan
	}

	if err := populateScanResults(store, sampleScans); err != nil {
		return fmt.Errorf("error populating results: %w", err)
	}

	// Mark scans as Completed and Update Protection Score
	for _, scan := range sampleScans {
		if err := store.UpdateScanStatusAndEndedAt(
			nil,
			scan.ID,
			enums.StatusCompleted.String(),
			scan.StartedAt.Add(time.Duration(gofakeit.IntRange(1, 100))),
		); err != nil {
			return fmt.Errorf("error updating scan status and ended at: %w", err)
		}

		// Give the scan a random protection score
		randScore := rand.Float64()
		if err := store.UpdateProtectionScore(scan.ID, randScore); err != nil {
			return fmt.Errorf("error updating protection score: %w", err)
		}

	}

	return nil
}

func populateScanResults(store interfaces.IStorage, sampleScans []domain.Scan) error {
	sampleInfoResults := samples.SampleInformationGatheringScanResults(sampleScans)
	sampleVulnResults := samples.SampleVulnerabilityAnalysisScanResults(sampleScans)

	// Insert Information Gathering results
	for _, result := range sampleInfoResults {
		if err := store.InsertScanResult(nil, &result); err != nil {
			slog.Error("failed to insert scan result", slog.String("scan_id", result.ScanID.String()))
			return fmt.Errorf("error populating information gathering results: %w", err)
		}
	}

	// Insert vulnerability Analysis results (and vulnerabilities)
	for _, result := range sampleVulnResults {
		if err := store.InsertVulnerabilityResult(&result); err != nil {
			return fmt.Errorf("error populating vulnerability results: %w", err)
		}
	}

	return nil
}

func main() {
	Run()
}

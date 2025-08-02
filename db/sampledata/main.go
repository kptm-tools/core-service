package main

import (
	"context"
	"fmt"
	"os"
	"math/rand"
	"os/exec"

	"github.com/kptm-tools/common/common/pkg/enums"
	migrations "github.com/kptm-tools/core-service/db/sql"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/samples"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
)

type PopulatorDependencies struct {
	HostRepo             interfaces.HostRepository
	ScanRepo             interfaces.ScanRepository
	CWERepo              interfaces.CWERepository
	CVERepo              interfaces.CVERepository
	VulnRepo             interfaces.VulnerabilityRepository
	OSRepo               interfaces.OSRepository
	ServiceRepo          interfaces.ServiceRepository
	ScanResRepo          interfaces.ScanResultRepository
	ScanService          interfaces.IScanService
	VulnerabilityService interfaces.IVulnerabilityService
}

func Run() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [populate|clear]")
		return
	}

	c := config.LoadConfig()
	store, err := storage.NewPostgreSQLStore(c, migrations.Migrations)
	if err != nil {
		panic(err)
	}
	scanService := services.NewScanService(store.Vulnerability, store.Scan, store.Host, store.ScanResult)
	vulnService := services.NewVulnerabilityService(store, store.OS, store.Service, store.Vulnerability, store.Scan, store.Host, store.Cve, store.Cwe)
	deps := PopulatorDependencies{
		HostRepo:             store.Host,
		ScanRepo:             store.Scan,
		CWERepo:              store.Cwe,
		CVERepo:              store.Cve,
		VulnRepo:             store.Vulnerability,
		OSRepo:               store.OS,
		ServiceRepo:          store.Service,
		ScanResRepo:          store.ScanResult,
		ScanService:          scanService,
		VulnerabilityService: vulnService,
	}

	command := os.Args[1]
	switch command {

	case "populate":
		populateDB(context.Background(), deps)
	default:
		fmt.Printf("Unknown command `%s`\n", command)
		fmt.Println("Usage: go run main.go [populate|clear]")
	}
}

func populateDB(ctx context.Context, deps PopulatorDependencies) {
	fmt.Println("Starting comprehensive database population...")

	// Step 1: Pre-populate CWE knowledge base first
	fmt.Println("Step 1/4: Pre-populating CWE knowledge base...")
	if err := populateCWEKnowledgeBase(); err != nil {
		panic(fmt.Errorf("failed to populate CWE knowledge base: %w", err))
	}
	fmt.Println("✅ CWE knowledge base populated successfully")

	// Step 2: Populate tenants
	fmt.Println("Step 2/4: Populating tenants...")
	tenants, err := populateTenants()
	if err != nil {
		panic(err)
	}
	fmt.Println("✅ Tenants populated successfully")

	// Step 3: Populate hosts
	fmt.Println("Step 3/4: Populating hosts...")
	hosts, errHost := populateHosts(ctx, deps.HostRepo, tenants)
	if errHost != nil {
		panic(errHost)
	}
	fmt.Println("✅ Hosts populated successfully")

	// Step 4: Populate scans with realistic vulnerability data
	fmt.Println("Step 4/4: Populating scans with realistic vulnerability data...")
	if err := populateScans(ctx, deps, tenants, hosts); err != nil {
		panic(err)
	}
	fmt.Println("✅ Scans populated successfully")
	
	fmt.Println("🎉 Database population completed successfully!")
}

// populateCWEKnowledgeBase executes the CWE pre-population script
func populateCWEKnowledgeBase() error {
	// Find the CWE JSON file (command runs from project root)
	cweFilePath := "data/cwe.json"
	
	// Verify the CWE file exists
	if _, err := os.Stat(cweFilePath); os.IsNotExist(err) {
		return fmt.Errorf("CWE JSON file not found at %s", cweFilePath)
	}

	// Execute the CWE population command using db_tool
	cmd := exec.Command("go", "run", "./db/db_tool/main.go", "populate-cwe")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to execute CWE population: %w", err)
	}

	return nil
}

func populateTenants() ([]domain.Tenant, error) {
	sampleTenants := samples.SampleTenants()

	return sampleTenants, nil
}

func populateHosts(
	ctx context.Context,
	hostRepo interfaces.HostRepository,
	tenants []domain.Tenant,
) ([]domain.Host, error) {
	sampleHosts := samples.SampleHosts(10, tenants)

	for i, host := range sampleHosts {
		createdHost, err := hostRepo.CreateHost(ctx, &host)
		if err != nil {
			return nil, fmt.Errorf("error populating host %s: %w", host.Name, err)
		}
		sampleHosts[i] = *createdHost
	}
	return sampleHosts, nil
}

func populateScans(
	ctx context.Context,
	deps PopulatorDependencies,
	tenants []domain.Tenant,
	hosts []domain.Host,
) error {
	sampleScans := samples.SampleScans(10, tenants, hosts)

	for i, scan := range sampleScans {
		createdScan, err := deps.ScanService.CreateScan(ctx, scan.HostID, scan.TenantID, scan.OperatorID, &scan.StartedAt)
		if err != nil {
			return fmt.Errorf("error populating scans: %w", err)
		}
		createdScan.EndedAt = scan.EndedAt
		sampleScans[i] = *createdScan
	}

	if err := populateNetworkOSVulnerabilities(ctx, deps, sampleScans); err != nil {
		return fmt.Errorf("error populating NetworkOSVulnerabilities: %w", err)
	}

	if err := populateWebScanVulnerabilities(ctx, deps, sampleScans); err != nil {
		return fmt.Errorf("error populating WebScanVulnerabilities: %w", err)
	}

	// Mark scans as Completed and Update Protection Score
	for _, scan := range sampleScans {
		if err := deps.ScanRepo.UpdateScanStatusAndEndedAt(
			ctx,
			scan.ID,
			enums.StatusCompleted,
			*scan.EndedAt,
		); err != nil {
			return fmt.Errorf("error updating scan status and ended at: %w", err)
		}

		// Give the scan a random protection score
		randScore := rand.Float64()
		if err := deps.ScanRepo.UpdateProtectionScore(ctx, scan.ID, randScore); err != nil {
			return fmt.Errorf("error updating protection score: %w", err)
		}

	}

	return nil
}

func populateNetworkOSVulnerabilities(
	ctx context.Context,
	deps PopulatorDependencies,
	scans []domain.Scan,
) error {
	for _, scan := range scans {
		sampleNmapResult := samples.SampleNmapScanResults(scan)
		err := deps.VulnerabilityService.CreateNetworkOSVulnerabilities(ctx, scan.ID, sampleNmapResult)
		if err != nil {
			return fmt.Errorf("failed to create networkOSVulnerability: %w", err)
		}
	}
	return nil
}

func populateWebScanVulnerabilities(
	ctx context.Context,
	deps PopulatorDependencies,
	scans []domain.Scan,
) error {
	for _, scan := range scans {
		sampleWebScanResult := samples.SampleWebScanResults()
		err := deps.VulnerabilityService.InsertWebScanVulnerabilities(ctx, scan.ID, sampleWebScanResult)
		if err != nil {
			return fmt.Errorf("failed to create webScanVulnerability: %w", err)
		}
	}
	return nil
}

func main() {
	Run()
}

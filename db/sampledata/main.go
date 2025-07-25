package main

import (
	"context"
	"fmt"
	"github.com/kptm-tools/common/common/pkg/enums"
	"github.com/kptm-tools/common/common/pkg/results/tools"
	migrations "github.com/kptm-tools/core-service/db/sql"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/samples"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
	"math/rand"
	"os"
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
	fmt.Println("Populating DB with sample data...")

	tenants, err := populateTenants()
	if err != nil {
		panic(err)
	}
	fmt.Println("Tenants populated successfully")

	hosts, errHost := populateHosts(ctx, deps.HostRepo, tenants)
	if errHost != nil {
		panic(errHost)
	}
	fmt.Println("Hosts populated successfully")

	fmt.Println("Populating scans...")
	if err := populateScans(ctx, deps, tenants, hosts); err != nil {
		panic(err)
	}
	fmt.Println("Scans populated successfully")
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

	cweDetails := samples.SampleCWEDetails()
	if err := populateNetworkOSVulnerabilities(ctx, deps, sampleScans, cweDetails); err != nil {
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
	cweDetails []tools.CWERemediation,
) error {
	for _, scan := range scans {
		sampleNmapResult := samples.SampleNmapScanResults(scan, cweDetails)
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

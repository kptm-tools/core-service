package main

import (
	"fmt"
	"os"

	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/samples"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [populate|clear]")
		return
	}

	c := config.LoadConfig()
	coreStore, err := storage.NewPostgreSQLStore(c.PostgreSQLCoreConnStr())
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

	if err := populateTenants(store); err != nil {
		panic(err)
	}
	fmt.Println("Tenants populated successfully")

	if err := populateHosts(store); err != nil {
		panic(err)
	}
	fmt.Println("Hosts populated successfully")

}

func populateTenants(store interfaces.IStorage) error {
	tenantService := services.NewTenantService(store)
	sampleTenants := samples.SampleTenants()

	for _, tenant := range sampleTenants {
		_, err := tenantService.CreateTenant(&tenant)
		if err != nil {
			return fmt.Errorf("error populating tenant %s: %w", tenant.ID, err)
		}
	}
	return nil
}

func populateHosts(store interfaces.IStorage) error {
	hostService := services.NewHostService(store)
	sampleHosts := samples.SampleHosts()

	for _, host := range sampleHosts {

		_, err := hostService.CreateHost(&host)
		if err != nil {
			return fmt.Errorf("error populating host %s: %w", host.Name, err)
		}
	}
	return nil
}

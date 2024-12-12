package main

import (
	"fmt"
	"log"
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
		log.Fatalf("Failed to create Core DB store: `%+v`", err)
	}

	command := os.Args[1]
	switch command {

	case "populate":
		populateDB(coreStore)
	case "clear":
		clearDB(coreStore)
	default:
		fmt.Printf("Unknown command `%s`\n", command)
		fmt.Println("Usage: go run main.go [populate|clear]")
	}

}

func clearDB(store interfaces.IStorage) {
	log.Println("Clearing DB...")
	log.Println("DB cleared")

}

func populateDB(store interfaces.IStorage) {
	log.Println("Populating DB with sample data...")

	if err := populateTenants(store); err != nil {
		log.Fatalf(err.Error())
	}
	log.Println("Tenants populated successfully")

}

func populateTenants(store interfaces.IStorage) error {
	tenantService := services.NewTenantService(store)
	sampleTenants := samples.SampleTenants()

	for _, tenant := range sampleTenants {
		_, err := tenantService.CreateTenant(&tenant)
		if err != nil {
			return fmt.Errorf("Error populating tenant `%+v`: `%v`\n", tenant, err)
		}
	}
	return nil
}

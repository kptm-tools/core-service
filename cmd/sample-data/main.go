package main

import (
	"fmt"
	"log"

	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/samples"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
)

func main() {
	c := config.LoadConfig()

	coreStore, err := storage.NewPostgreSQLStore(c.PostgreSQLCoreConnStr())
	if err != nil {
		log.Fatalf("Failed to create Core DB store: `%+v`", err)
	}

	// Services
	tenantService := services.NewTenantService(coreStore)

	fmt.Println("Populating DB with sample data...")

	// Add Sample Tenants
	sampleTenants := samples.SampleTenants()

	for _, tenant := range sampleTenants {
		_, err := tenantService.CreateTenant(&tenant)
		if err != nil {
			log.Printf("Error populating tenant `%+v`: `%v`\n", tenant, err)
		}
	}
	log.Println("Tenants added successfully")

}

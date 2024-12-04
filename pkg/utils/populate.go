package utils

import (
	"fmt"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"net/http"
	"os"
)

func OpenAndReadKickstartJson(tenantService interfaces.ITenantService) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		return "Can not access to path", err
	}
	fmt.Println("Current working directory:", dir)
	jsonFile, err := os.Open(dir + "/pkg/utils/fusionauth/kickstart/kickstart.json")

	if err != nil {
		fmt.Println(err)
		return "Not found file", err
	}
	defer jsonFile.Close()
	data, err := readFileJson(jsonFile)
	if err != nil {
		return "Bad read", err
	}
	tenantIDs := make([]string, 0)
	applicationIDs := make([]string, 0)
	tenantIDs = parseMap(data, "tenant", tenantIDs)
	applicationIDs = parseMap(data, "applicationUuid", applicationIDs)
	for i := 0; i < len(tenantIDs); i++ {

		tenant := domain.NewTenant(tenantIDs[i], applicationIDs[i])
		fmt.Println(tenant)
		tenantService.CreateTenant(tenant)

	}
	return "Good", nil
}

func buildFusionAuthGetTenantsRequest() (*http.Request, error) {
	c := config.LoadConfig()
	apiKey := c.FusionAuthAPIKey
	url := fmt.Sprintf("http://%s:%s/api/tenant", c.FusionAuthHost, c.FusionAuthPort)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	return req, nil
}

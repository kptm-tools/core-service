package utils
import (
	"fmt"
	"os"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/config"
	"net/http"
)

func openAndReadKickstartJson(tenantService interfaces.ITenantService, appID string) (string, error){
    jsonFile, err := os.Open("utils/fusionauth/kickstart/kickstart.json")
	
	if err != nil {
		fmt.Println(err)
		return "Not found file", err
	}
	defer jsonFile.Close()
    data, err := readFileJson(jsonFile)
	if err != nil {
		return "Bad read", err
	}
	parseMap(data,"tenant", tenantService, appID)
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
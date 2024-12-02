package utils
import (
	"fmt"
	"os"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

func openAndReadKickstartJson(tenantService interfaces.ITenantService, appID string){
    jsonFile, err := os.Open("utils/fusionauth/kickstart/kickstart.json")
	
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
    data, err := readFileJson(jsonFile)
	parseMap(data,"tenant", tenantService, appID)
}
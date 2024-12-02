package utils

import (
	"encoding/json"
    "io"
	"io/ioutil"
	"fmt"
    "strings"
    "github.com/kptm-tools/core-service/pkg/interfaces"
    "github.com/kptm-tools/core-service/pkg/domain"
)



func readFileJson(readerJsonFile io.Reader) (map[string]interface{}, error){
	
	byteValue, err := ioutil.ReadAll(readerJsonFile)
	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)
	return result, err
}


func parseMap(aMap map[string]interface{}, searchWord string, tenantService interfaces.ITenantService, appID string) {
    for key, val := range aMap {
        switch concreteVal := val.(type) {
        case map[string]interface{}:
            parseMap(val.(map[string]interface{}),searchWord, tenantService, appID)
        case []interface{}:
            parseArray(val.([]interface{}),searchWord, tenantService, appID)

        default:
            strVal := concreteVal.(string)
            if strings.Contains(key, searchWord) {
                tenant := domain.NewTenant(strVal, appID)
                fmt.Println(tenant)
                tenantService.CreateTenant(tenant)
            }
            //fmt.Println(key, "v:", concreteVal)
        }
    }
}

func parseArray(anArray []interface{},searchWord string, tenantService interfaces.ITenantService, appID string) {
    for i, val := range anArray {
        switch concreteVal := val.(type) {
        case map[string]interface{}:
            parseMap(val.(map[string]interface{}),searchWord, tenantService, appID)
        case []interface{}:
            parseArray(val.([]interface{}), searchWord, tenantService, appID)
        default:
            fmt.Println("Index", i, ":", concreteVal)
        }
    }
}


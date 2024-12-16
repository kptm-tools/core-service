package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func readFileJSON(readerJSONFile io.Reader) (map[string]interface{}, error) {

	byteValue, err := io.ReadAll(readerJSONFile)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	err = json.Unmarshal([]byte(byteValue), &result)
	if err != nil {
		return nil, err
	}
	return result, err
}

func parseMap(aMap map[string]interface{}, searchWord string, tenantIDs []string) []string {
	for key, val := range aMap {
		switch concreteVal := val.(type) {
		case map[string]interface{}:
			tenantIDs = parseMap(val.(map[string]interface{}), searchWord, tenantIDs)
		case []interface{}:
			tenantIDs = parseArray(val.([]interface{}), searchWord, tenantIDs)
		default:
			if strVal, ok := concreteVal.(string); ok {
				if strings.Contains(key, searchWord) && !strings.Contains(strVal, "#") {
					tenantIDs = append(tenantIDs, strVal)
				}
			}
		}
	}
	return tenantIDs
}

func parseArray(anArray []interface{}, searchWord string, tenantsIDs []string) []string {
	for _, val := range anArray {
		switch concreteVal := val.(type) {
		case map[string]interface{}:
			tenantsIDs = parseMap(val.(map[string]interface{}), searchWord, tenantsIDs)
		case []interface{}:
			parseArray(val.([]interface{}), searchWord, tenantsIDs)
		default:
			if strVal, ok := concreteVal.(string); ok {
				if strings.Contains(strVal, searchWord) {
					fmt.Println("")
				}
			}
		}
	}
	return tenantsIDs
}

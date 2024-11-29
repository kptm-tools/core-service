package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/handlers"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type AuthService struct {
}

var _ interfaces.IAuthService = (*AuthService)(nil)

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) Login(email, password, applicationID string) (*http.Response, error) {

	// Make a POST request to FusionAuth including credentials as body
	// and APIKey in headers

	// Build request
	req, err := buildFusionAuthLoginRequest(email, password, applicationID)

	if err != nil {
		return nil, err
	}

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func buildFusionAuthLoginRequest(email, password, applicationID string) (*http.Request, error) {
	c := config.LoadConfig()

	apiKey := c.FusionAuthAPIKey
	url := fmt.Sprintf("http://%s:%s/api/login", c.FusionAuthHost, c.FusionAuthPort)

	// Connect to fusionauth and return the response

	body := handlers.FusionAuthLoginRequest{
		LoginID:       email,
		Password:      password,
		ApplicationID: applicationID,
	}

	jsonData, err := json.Marshal(body)

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))

	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)

	return req, nil

}

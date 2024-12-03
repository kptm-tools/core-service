package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
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

func (s *AuthService) RegisterTenant(tenantName string) (*domain.Tenant, error) {

	fmt.Println("Attempting to register Tenant with name: ", tenantName)
	c := config.LoadConfig()

	host := fmt.Sprintf("http://%s:%s", c.FusionAuthHost, c.FusionAuthPort)
	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}

	baseURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	client := fusionauth.NewClient(httpClient, baseURL, c.FusionAuthAPIKey)

	// Fetch blueprint tenant by it's ID
	fmt.Println("Trying to fetch blueprint tenant with ID: ", c.BlueprintTenantID)
	resp, faErr, err := client.RetrieveTenant(c.BlueprintTenantID)

	if err != nil {
		return nil, err
	}

	if faErr != nil {
		return nil, fmt.Errorf("Encountered a FusionAuth Error: `%+v`", faErr.Error())
	}

	// Use this blueprint to build a new tenant with our name
	tenantID := uuid.NewString()
	tenant := &fusionauth.Tenant{
		Id:                              tenantID,
		Name:                            tenantName,
		ThemeId:                         resp.Tenant.ThemeId,
		Issuer:                          resp.Tenant.Issuer,
		JwtConfiguration:                resp.Tenant.JwtConfiguration,
		ExternalIdentifierConfiguration: resp.Tenant.ExternalIdentifierConfiguration,
		EmailConfiguration:              resp.Tenant.EmailConfiguration,
		MultiFactorConfiguration:        resp.Tenant.MultiFactorConfiguration,
	}

	// Fetch blueprint app
	appResp, err := client.RetrieveApplication(c.BlueprintApplicationID)

	if err != nil {
		return nil, err
	}
	// fmt.Printf("Got BlueprintAPP `%+v`\n", appResp)

	// Use this blueprint to build a new App and assign it to our tenant
	appID := uuid.NewString()
	app := &fusionauth.Application{
		Id:                        appID,
		TenantId:                  tenantID,
		Name:                      fmt.Sprintf("%s App", tenantName),
		OauthConfiguration:        appResp.Application.OauthConfiguration,
		JwtConfiguration:          appResp.Application.JwtConfiguration,
		RegistrationConfiguration: appResp.Application.RegistrationConfiguration,
		// Roles:                     appResp.Application.Roles,
	}

	// Create mock users

	// Register this tenant to fusionAuth
	tenantReq := fusionauth.TenantRequest{Tenant: *tenant}
	resp, faErr, err = client.CreateTenant(tenantID, tenantReq)
	// TODO: Handle errors
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, fmt.Errorf("Encountered a FusionAuth Error: `%+v`", faErr.Error())
	}
	fmt.Printf("%d: CreateTenant `%s`\n", resp.StatusCode, tenantID)

	// 3. Create a mock application for this tenant
	client.SetTenantId(tenantID)

	// 3.1 Create an assymetric API KEY for JWT Config of the App and assign it to the New Tenant
	keyID := uuid.New().String()
	key := fusionauth.Key{
		Algorithm: fusionauth.KeyAlgorithm_RS256,
		Length:    2048,
		Name:      fmt.Sprintf("For %s App", tenantName),
		Id:        keyID,
	}
	keyReq := fusionauth.KeyRequest{Key: key}

	_, faErr, err = client.GenerateKey(keyID, keyReq)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, fmt.Errorf("Encountered a FusionAuth Error: `%+v`", faErr.Error())
	}

	// 3.1.1 TODO: handle key generation errors

	// fmt.Println("POST Key Response: ", keyResp)

	// 3.2 Copy the BlueprintAPP

	app.JwtConfiguration.AccessTokenKeyId = keyID
	app.JwtConfiguration.IdTokenKeyId = keyID

	appReq := fusionauth.ApplicationRequest{Application: *app}
	appResp, faErr, err = client.CreateApplication(appID, appReq)
	// TODO: Handle errors
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, fmt.Errorf("Encountered a FusionAuth Error: `%+v`", faErr.Error())
	}

	// TODO: FIX ERROR WHEN CREATING APP
	// "Encountered a FusionAuth Error: `A tenant Id is required to complete this request. To complete this request, you may assign a tenant to your API key, or add the X-FusionAuth-TenantId HTTP request header with the tenant Id.`"
	fmt.Printf("%d: CreateApp `%s`\n", appResp.StatusCode, appID)

	// Parse fusionauth Tenant Object into Domain Tenant Object

	domainTenant := domain.NewTenant(tenantID, appID)

	return domainTenant, nil
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

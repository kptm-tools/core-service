package services

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/google/uuid"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
)

type FaError struct {
	status int
	msg    string
}

func (e *FaError) Error() string {
	return e.msg
}

func (e *FaError) Status() int {
	return e.status
}

func NewFaError(status int, msg string) *FaError {
	return &FaError{
		status: status,
		msg:    msg,
	}
}

type AuthService struct {
}

var _ interfaces.IAuthService = (*AuthService)(nil)

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) Login(email, password, applicationID string) (*fusionauth.LoginResponse, error) {

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

	loginReq := fusionauth.LoginRequest{
		BaseLoginRequest: fusionauth.BaseLoginRequest{
			ApplicationId: applicationID,
		},
		LoginId:  email,
		Password: password,
	}

	// Use FusionAuth Go client to log in the user
	loginResponse, faErr, err := client.Login(loginReq)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(loginResponse.StatusCode, faErr.Error())
	}

	return loginResponse, nil

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
		return nil, NewFaError(resp.StatusCode, faErr.Error())
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
	var roles []fusionauth.ApplicationRole
	for _, r := range appResp.Application.Roles {
		role := fusionauth.ApplicationRole{
			Name:        r.Name,
			Description: r.Description,
			IsDefault:   r.IsDefault,
			IsSuperRole: r.IsSuperRole,
		}
		roles = append(roles, role)
	}

	app := &fusionauth.Application{
		Id:                        appID,
		TenantId:                  tenantID,
		Name:                      fmt.Sprintf("%s App", tenantName),
		OauthConfiguration:        appResp.Application.OauthConfiguration,
		JwtConfiguration:          appResp.Application.JwtConfiguration,
		RegistrationConfiguration: appResp.Application.RegistrationConfiguration,
		Roles:                     roles,
	}

	// Register this tenant to fusionAuth
	tenantReq := fusionauth.TenantRequest{Tenant: *tenant}
	resp, faErr, err = client.CreateTenant(tenantID, tenantReq)
	// TODO: Handle errors
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}
	// fmt.Printf("%d: CreateTenant `%s`\n", resp.StatusCode, tenantID)

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

	// 3.1.1 Handle key generation errors
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}

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
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}

	// Create initial operator user

	if err := createInitialUser(appID, client); err != nil {
		return nil, err
	}

	// Parse fusionauth Tenant Object into Domain Tenant Object
	domainTenant := domain.NewTenant(tenantID, appID)

	return domainTenant, nil
}

func createInitialUser(appID string, client *fusionauth.FusionAuthClient) error {

	email := "operator@example.com"
	pass := uuid.NewString()
	roles := []string{"operator"}

	userReq := fusionauth.UserRequest{
		ApplicationId: appID,
		User: fusionauth.User{
			Email:          email,
			SecureIdentity: fusionauth.SecureIdentity{Password: pass},

			Registrations: []fusionauth.UserRegistration{
				{
					ApplicationId: appID,
					Roles:         roles,
				},
			},
		},
	}

	resp, faErr, err := client.CreateUser("", userReq)
	if err != nil {
		return err
	}
	if faErr != nil {
		return NewFaError(resp.StatusCode, faErr.Error())
	}

	return nil
}

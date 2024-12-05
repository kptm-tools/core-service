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
	client *http.Client
}

var _ interfaces.IAuthService = (*AuthService)(nil)

func NewAuthService() *AuthService {
	return &AuthService{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *AuthService) Login(email, password, applicationID string) (*fusionauth.LoginResponse, error) {

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

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

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

	// Fetch blueprint tenant by it's ID
	bpTenant, err := fetchBlueprintTenant(client)

	// Use this blueprint to build a new tenant with our name
	// and register this tenant to fusionAuth
	tenant, err := createTenantFromBlueprint(tenantName, bpTenant, client)
	if err != nil {
		return nil, err
	}

	// Fetch blueprint app
	bpApp, err := fetchBlueprintApp(client)
	if err != nil {
		return nil, err
	}

	// Use this blueprint to build a new App and assign it to our tenant
	client.SetTenantId(tenant.Id)
	// Unset key
	defer client.SetTenantId("")
	app, err := createAppFromBlueprint(tenant, bpApp, client)
	if err != nil {
		return nil, err
	}

	// Create initial operator user
	_, err = createInitialUser(app.Id, client)
	if err != nil {
		return nil, err
	}

	// Parse fusionauth Tenant Object into Domain Tenant Object
	domainTenant := domain.NewTenant(tenant.Id, app.Id)

	return domainTenant, nil
}

// TODO: Use a shared http.Client for authService
func fetchBlueprintTenant(client *fusionauth.FusionAuthClient) (*fusionauth.Tenant, error) {
	c := config.LoadConfig()

	// log.Println("Trying to fetch blueprint tenant with ID: ", c.BlueprintTenantID)
	resp, faErr, err := client.RetrieveTenant(c.BlueprintTenantID)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}

	t := &resp.Tenant

	return t, nil
}

func createTenantFromBlueprint(tenantName string, bpTenant *fusionauth.Tenant, client *fusionauth.FusionAuthClient) (*fusionauth.Tenant, error) {
	tenantID := uuid.NewString()
	tenant := &fusionauth.Tenant{
		Id:                              tenantID,
		Name:                            tenantName,
		ThemeId:                         bpTenant.ThemeId,
		Issuer:                          bpTenant.Issuer,
		JwtConfiguration:                bpTenant.JwtConfiguration,
		ExternalIdentifierConfiguration: bpTenant.ExternalIdentifierConfiguration,
		EmailConfiguration:              bpTenant.EmailConfiguration,
		MultiFactorConfiguration:        bpTenant.MultiFactorConfiguration,
	}

	if err := registerTenant(tenant, client); err != nil {
		return nil, err
	}
	return tenant, nil
}

func registerTenant(t *fusionauth.Tenant, client *fusionauth.FusionAuthClient) error {
	tenantReq := fusionauth.TenantRequest{Tenant: *t}
	resp, faErr, err := client.CreateTenant(t.Id, tenantReq)

	if err != nil {
		return err
	}
	if faErr != nil {
		return NewFaError(resp.StatusCode, faErr.Error())
	}

	return nil
}

func fetchBlueprintApp(client *fusionauth.FusionAuthClient) (*fusionauth.Application, error) {
	c := config.LoadConfig()

	resp, err := client.RetrieveApplication(c.BlueprintApplicationID)
	if err != nil {
		return nil, err
	}

	a := &resp.Application
	// log.Printf("Got BlueprintAPP `%+v`\n", a)
	return a, nil
}

func createAppFromBlueprint(tenant *fusionauth.Tenant, bpApp *fusionauth.Application, client *fusionauth.FusionAuthClient) (*fusionauth.Application, error) {

	appID := uuid.NewString()
	var roles []fusionauth.ApplicationRole
	for _, r := range bpApp.Roles {
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
		TenantId:                  tenant.Id,
		Name:                      fmt.Sprintf("%s App", tenant.Name),
		OauthConfiguration:        bpApp.OauthConfiguration,
		JwtConfiguration:          bpApp.JwtConfiguration,
		RegistrationConfiguration: bpApp.RegistrationConfiguration,
		Roles:                     roles,
	}

	// Create a new key for this new app
	key, err := generateKey(tenant, client)
	if err != nil {
		return nil, err
	}

	// Add the key to this new app
	app.JwtConfiguration.AccessTokenKeyId = key.Id
	app.JwtConfiguration.IdTokenKeyId = key.Id

	err = registerApp(app, client)
	if err != nil {
		return nil, err
	}

	return app, nil
}

func registerApp(a *fusionauth.Application, client *fusionauth.FusionAuthClient) error {
	req := fusionauth.ApplicationRequest{Application: *a}
	resp, faErr, err := client.CreateApplication(a.Id, req)

	if err != nil {
		return err
	}
	if faErr != nil {
		return NewFaError(resp.StatusCode, faErr.Error())
	}
	return nil
}

func generateKey(tenant *fusionauth.Tenant, client *fusionauth.FusionAuthClient) (*fusionauth.Key, error) {
	keyID := uuid.NewString()
	key := fusionauth.Key{
		Algorithm: fusionauth.KeyAlgorithm_RS256,
		Length:    2048,
		Name:      fmt.Sprintf("For %s App", tenant.Name),
		Id:        keyID,
	}
	keyReq := fusionauth.KeyRequest{Key: key}

	resp, faErr, err := client.GenerateKey(keyID, keyReq)

	// 3.1.1 Handle key generation errors
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}
	return &resp.Key, nil
}

func createInitialUser(appID string, client *fusionauth.FusionAuthClient) (*fusionauth.User, error) {

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
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}

	return &resp.User, nil
}

func (s *AuthService) NewFusionAuthClient() (*fusionauth.FusionAuthClient, error) {

	c := config.LoadConfig()
	host := fmt.Sprintf("http://%s:%s", c.FusionAuthHost, c.FusionAuthPort)
	baseURL, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("Error creating FusionAuthClient: `%s`", err.Error())
	}

	return fusionauth.NewClient(s.client, baseURL, c.FusionAuthAPIKey), nil
}

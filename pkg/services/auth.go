package services

import (
	"errors"
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
	client  *http.Client
	storage interfaces.IStorage
}

var _ interfaces.IAuthService = (*AuthService)(nil)

func NewAuthService(storage interfaces.IStorage) *AuthService {
	return &AuthService{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		storage: storage,
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

func (s *AuthService) RegisterTenant(tenantName string) (*domain.Tenant, *domain.User, error) {

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, nil, err
	}

	// Fetch blueprint tenant by it's ID
	bpTenant, err := fetchBlueprintTenant(client)

	// Use this blueprint to build a new tenant with our name
	// and register this tenant to fusionAuth
	tenant, err := createTenantFromBlueprint(tenantName, bpTenant, client)
	if err != nil {
		return nil, nil, err
	}

	// Fetch blueprint app
	bpApp, err := fetchBlueprintApp(client)
	if err != nil {
		return nil, nil, err
	}

	// Use this blueprint to build a new App and assign it to our tenant
	client.SetTenantId(tenant.Id)
	// Unset key
	defer client.SetTenantId("")

	app, err := createAppFromBlueprint(tenant, bpApp, client)
	if err != nil {
		return nil, nil, err
	}

	// Create initial operator user
	domainUser, err := createInitialUser(app.Id, client)
	if err != nil {
		return nil, nil, err
	}

	// Parse fusionauth Tenant Object into Domain Tenant Object
	domainTenant := domain.NewTenant(tenant.Id, app.Id)

	// Store the domainTenant in our Database
	domainTenant, err = s.storage.CreateTenant(domainTenant)
	if err != nil {
		return nil, nil, err
	}

	return domainTenant, domainUser, nil
}

func (s *AuthService) GetUserByID(userID string, tenantID *string) (*domain.User, error) {
	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

	// Optional parameter
	if tenantID != nil {
		client.SetTenantId(*tenantID)
		defer client.SetTenantId("")
	}

	resp, faErr, err := client.RetrieveUser(userID)
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(resp.StatusCode, faErr.Error())
	}

	u, err := scanIntoDomainUser(resp.User)
	if err != nil {
		return nil, err
	}

	return u, nil
}

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

func createInitialUser(appID string, client *fusionauth.FusionAuthClient) (*domain.User, error) {

	email := "operator@example.com"
	pass := uuid.NewString()
	roles := []string{"operator"}

	registerReq := fusionauth.RegistrationRequest{
		User: fusionauth.User{
			Email:          email,
			SecureIdentity: fusionauth.SecureIdentity{Password: pass},
		},
		Registration: fusionauth.UserRegistration{
			ApplicationId: appID,
			Roles:         roles,
		},
	}

	regResp, faErr, err := client.Register("", registerReq)
	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(regResp.StatusCode, faErr.Error())
	}

	u := &regResp.User
	return domain.NewUser(u.Id, email, pass, u.TenantId, appID, roles), nil
}

func scanIntoDomainUser(faUser fusionauth.User) (*domain.User, error) {
	// Get AppID and Roles from Registrations

	var appID string
	roles := []string{}

	if len(faUser.Registrations) == 0 {
		return nil, errors.New("fusionauth user has no registrations")
	}

	appID = faUser.Registrations[0].ApplicationId

	for _, role := range faUser.Registrations[0].Roles {
		// Validate role string
		_, err := domain.ParseRole(role)
		if err != nil {
			return nil, err
		}

		roles = append(roles, role)
	}

	u := domain.NewUser(faUser.Id, faUser.Email, faUser.Password, faUser.TenantId, appID, roles)
	return u, nil
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

func (s *AuthService) ForgotPassword(email, applicationID string) (*fusionauth.ForgotPasswordResponse, error) {

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

	forgotReq := fusionauth.ForgotPasswordRequest{
		ApplicationId:           applicationID,
		SendForgotPasswordEmail: true,
		LoginId:                 email,
	}

	// Use FusionAuth Go client to log in the user
	forgotResponse, faErr, err := client.ForgotPassword(forgotReq)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(forgotResponse.StatusCode, faErr.Error())
	}

	return forgotResponse, nil

}

func (s *AuthService) RegisterUser() (*fusionauth.RegistrationResponse, error) {

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

	registerReq := fusionauth.RegistrationRequest{}

	// Use FusionAuth Go client to log in the user
	registerResponse, faErr, err := client.Register("", registerReq)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(registerResponse.StatusCode, faErr.Error())
	}

	return registerResponse, nil

}
func (s *AuthService) SendEmailRegistration() (*fusionauth.SendResponse, error) {

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

	sendReq := fusionauth.SendRequest{}

	// Use FusionAuth Go client to log in the user
	sendResponse, faErr, err := client.SendEmail("", sendReq)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(sendResponse.StatusCode, faErr.Error())
	}

	return sendResponse, nil

}

func (s *AuthService) VerifyEmail() (*fusionauth.BaseHTTPResponse, error) {

	client, err := s.NewFusionAuthClient()
	if err != nil {
		return nil, err
	}

	verifyEmailReq := fusionauth.VerifyEmailRequest{
		BaseEventRequest: fusionauth.BaseEventRequest{},
		OneTimeCode:      "",
		UserId:           "",
		VerificationId:   "",
	}

	// Use FusionAuth Go client to log in the user
	verificationResponse, faErr, err := client.VerifyEmailAddress(verifyEmailReq)

	if err != nil {
		return nil, err
	}
	if faErr != nil {
		return nil, NewFaError(verificationResponse.StatusCode, faErr.Error())
	}

	return verificationResponse, nil

}

package mocks

import (
	"github.com/FusionAuth/go-client/pkg/fusionauth"
	"github.com/kptm-tools/core-service/pkg/auth"
	"github.com/kptm-tools/core-service/pkg/domain"
	"net/http"
)

type MockAuthService struct {
	MockVerifyOTP          func(otp string) bool
	MockCheckOriginAllowed func(r *http.Request) bool
}

func (m *MockAuthService) Login(email, password, applicationID string) (*fusionauth.LoginResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) RegisterTenant(tenantName string) (*domain.Tenant, *domain.User, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) GetUserByID(userID string, tenantID *string) (*domain.User, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) ForgotPassword(email, applicationID string) (*fusionauth.ForgotPasswordResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) RegisterUser(firstname, lastname, email, password, applicationID string, roles []string) (*fusionauth.RegistrationResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) ChangePassword(changePasswordID, password, email, applicationID string) (*fusionauth.ChangePasswordResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) VerifyEmail(verificationID, tenantID string) (*fusionauth.BaseHTTPResponse, error) {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) GenerateOTP() auth.OTP {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) CheckOriginAllowed(r *http.Request) bool {
	//TODO implement me
	panic("implement me")
}

func (m *MockAuthService) VerifyOTP(otp string) bool {
	if m.MockVerifyOTP != nil {
		return m.MockVerifyOTP(otp)
	}
	return true
}

package handlers

import "github.com/kptm-tools/core-service/pkg/domain"

type CreateHostRequest struct {
	Value       string              `json:"value"`
	Name        string              `json:"name"`
	ValueType   string              `json:"value_type"`
	Credentials []domain.Credential `json:"credentials"`
	Rapporteurs []domain.Rapporteur `json:"rapporteurs"`
}

type ValidateHostRequest struct {
	Value    string `json:"value"`
	Hostname string `json:"hostname"`
}

type GetHostByTenantIDRequest struct {
	TenantID string `json:"tenant_id"`
}

type LoginRequest struct {
	LoginID       string `json:"loginId"`
	Password      string `json:"password"`
	ApplicationID string `json:"application_id"`
}

type RegisterTenantRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ForgotPasswordRequest struct {
	LoginID       string `json:"login_id"`
	ApplicationID string `json:"application_id"`
}

type ChangePasswordRequest struct {
	LoginID          string `json:"login_id"`
	Password         string `json:"password"`
	ChangePasswordID string `json:"change_password_id"`
	ApplicationID    string `json:"application_id"`
}

type VerifyEmailRequest struct {
	VerificationID string `json:"verification_id"`
}

type RegisterUserRequest struct {
	FirstName string   `json:"firstname"`
	LastName  string   `json:"lastname"`
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Roles     []string `json:"roles"`

	ApplicationID string `json:"application_id"`
}

type ServiceHost struct {
	Names []string `json:"names"`
	Host  string   `json:"host"`
}
type ScanRequest struct {
	HostIds []string `json:"host_ids"`
}

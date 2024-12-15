package handlers

type CreateHostRequest struct {
	TenantID   string `json:"tenant_id"`
	OperatorID string `json:"operator_id"`
	Value      string `json:"value"`
	Name       string `json:"name"`
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

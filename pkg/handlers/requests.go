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
	ApplicationID string `json:"applicationId"`
}

type RegisterTenantRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type ForgotPasswordRequest struct {
	LoginID       string `json:"loginId"`
	ApplicationID string `json:"applicationId"`
}

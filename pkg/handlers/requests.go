package handlers

type CreateTargetRequest struct {
	TenantID   string `json:"tenant_id"`
	OperatorID string `json:"operator_id"`
	Value      string `json:"value"`
}

type GetTargetByTenantIDRequest struct {
	TenantID string `json:"tenant_id"`
}

type LoginRequest struct {
	LoginID       string `json:"loginId"`
	Password      string `json:"password"`
	ApplicationID string `json:"applicationId"`
}

type FusionAuthLoginRequest struct {
	LoginID       string `json:"loginId"`
	Password      string `json:"password"`
	ApplicationID string `json:"applicationId"`
}

type FusionAuthPostTenantRequest struct {
	Name          string `json:"name"`
	Password      string `json:"password"`
	ApplicationID string `json:"applicationId"`
}

type RegisterTenantRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

package handlers

type CreateTargetRequest struct {
	TenantID   string `json:"tenant_id"`
	OperatorID string `json:"operator_id"`
	Value      string `json:"value"`
}

type GetTargetByTenantIDRequest struct {
	TenantID string `json:"tenant_id"`
}

package auth

import "github.com/FusionAuth/go-client/pkg/fusionauth"

type LoginResponse struct {
	Token                  string          `json:"token"`
	TokenExpirationInstant int64           `json:"tokenExpirationInstant"`
	User                   fusionauth.User `json:"user"`
	TenantID               string          `json:"tenantId"`
	OTPKey                 string          `json:"otp"`
}

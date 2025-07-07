package auth

import "github.com/FusionAuth/go-client/pkg/fusionauth"

// LoginResponse is returned after a successful authentication.
// @name LoginResponse
type LoginResponse struct {
	// Token is the JWT to be used for subsequent requests.
	// example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
	Token string `json:"token"`

	// TokenExpirationInstant is the RFC3339 timestamp when the token expires.
	// example: 2025-07-07T20:15:30Z
	TokenExpirationInstant int64 `json:"tokenExpirationInstant"`

	// User contains basic information about the authenticated user.
	// Uses our local wrapper so swag can generate a schema for it.
	User fusionauth.User `json:"user"`

	// TenantID identifies the tenant to which the user belongs.
	// example: 123e4567-e89b-12d3-a456-426614174000
	TenantID string `json:"tenantId"`

	// OTPKey is the secret key used to generate the one‑time password.
	// example: JBSWY3DPEHPK3PXP
	OTPKey string `json:"otp"`
}

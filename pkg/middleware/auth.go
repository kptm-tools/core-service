package middleware

import (
	"crypto/rsa"
	"errors"
)

var ErrInvalidToken = errors.New("invalid token")

var ErrNoToken = errors.New("token not found")

var ErrUserNotFound = errors.New("user not found")

var VerifyKey *rsa.PublicKey

type ContextKey string

const (
	ContextTenantID ContextKey = "tenantID"
	ContextUserID   ContextKey = "userID"
	ContextRoles    ContextKey = "userRoles"
)

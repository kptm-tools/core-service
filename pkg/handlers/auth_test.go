package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
	mock_services "github.com/kptm-tools/core-service/pkg/mocks/services"
	"github.com/stretchr/testify/assert"
)

func Test_getRequestToken(t *testing.T) {
	tests := []struct {
		name      string
		request   func() *http.Request
		wantToken string
		wantErr   error
	}{
		{
			name: "Token in header",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer test-token")
				return r
			},
			wantToken: "test-token",
			wantErr:   nil,
		},
		{
			name: "Token in cookie",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(&http.Cookie{Name: "app.at", Value: "test-token"})
				return r
			},
			wantToken: "test-token",
			wantErr:   nil,
		},
		{
			name: "No token provided",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantToken: "",
			wantErr:   middleware.ErrNoToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.request()
			token, err := getRequestToken(req)

			if token != tt.wantToken {
				t.Errorf("Expected token `%v`, got `%v`", tt.wantToken, token)
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Expected error `%v`, got `%v`", tt.wantErr, err)
			}
		})
	}
}

func Test_checkTokenRoles(t *testing.T) {
	tests := []struct {
		name         string
		tokenClaims  jwt.MapClaims
		functionName domain.Action
		wantErr      error
	}{
		{
			name: "Valid roles",
			tokenClaims: jwt.MapClaims{
				"roles": []interface{}{"admin"},
			},
			functionName: domain.ActionUserGet,
			wantErr:      nil,
		},
		{
			name: "Invalid roles",
			tokenClaims: jwt.MapClaims{
				"roles": []interface{}{"user"},
			},
			functionName: domain.ActionDashboardGet,
			wantErr:      middleware.ErrInvalidToken,
		},
		{
			name: "Empty roles",
			tokenClaims: jwt.MapClaims{
				"roles": []interface{}{},
			},
			functionName: domain.ActionDashboardGet,
			wantErr:      middleware.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tt.tokenClaims,
			}
			_, err := checkTokenRoles(token, tt.functionName)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func Test_validateTokenSignature(t *testing.T) {
	tests := []struct {
		name    string
		token   *jwt.Token
		wantErr error
	}{
		{
			name:    "Valid token signature",
			token:   jwt.New(jwt.SigningMethodRS256),
			wantErr: nil,
		},
		{
			name:    "Invalid token signature",
			token:   jwt.New(jwt.SigningMethodEdDSA),
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name:    "Invalid token signature",
			token:   jwt.New(jwt.SigningMethodES256),
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name:    "Valid token signature within RSA family",
			token:   jwt.New(jwt.SigningMethodRS512),
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSigningMethod(tt.token)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Expected error `%v`, got `%v`", tt.wantErr, err)
			}
		})
	}
}

func Test_validateClaims(t *testing.T) {
	tests := []struct {
		name         string
		tokenClaims  jwt.MapClaims
		tokenHeaders map[string]interface{}
		wantErr      error
	}{
		{
			name: "Token with valid claims",
			tokenClaims: jwt.MapClaims{
				"iss": "https://app.kriptome.com",
				"tid": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
				"sub": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: nil,
		},
		{
			name: "Token with invalid issuer",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
				"tid": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
				"sub": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name: "Token with no token headers",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
				"tid": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
				"sub": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{},
			wantErr:      middleware.ErrInvalidToken,
		},
		{
			name: "Token with empty kid header",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
				"tid": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
				"sub": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "",
			},
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name:        "Token with empty claims",
			tokenClaims: jwt.MapClaims{},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name:        "Token with no claims",
			tokenClaims: nil,
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name: "Token with no iss claim",
			tokenClaims: jwt.MapClaims{
				"tid": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
				"sub": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name: "Token with no userID claim",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
				"tid": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: middleware.ErrInvalidToken,
		},
		{
			name: "Token with no tenantID claim",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
				"sub": "b2131c96-bc4d-4dab-86c8-e5ff3e70b3f9",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: middleware.ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tt.tokenClaims,
				Header: tt.tokenHeaders,
			}

			err := validateClaims(token, "https://app.kriptome.com")
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Expected error `%v`, got `%v`", tt.wantErr, err)
			}
		})
	}
}

func TestAuthHandlers_GetUserPermissions(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		authService interfaces.IAuthService
		// Named input parameters for target function.
		r          *http.Request
		wantStatus int
	}{
		{
			name:        "Request with valid roles on token",
			authService: &mock_services.MockAuthService{},
			r: httptest.NewRequest("GET", "/api/user/permissions", nil).WithContext(
				context.WithValue(
					context.Background(),
					middleware.ContextRoles,
					[]domain.Role{domain.RoleAdmin},
				),
			),
			wantStatus: http.StatusOK,
		},
		{
			name:        "Request with uncastable roles on context token returns unauthorized",
			authService: &mock_services.MockAuthService{},
			r: httptest.NewRequest("GET", "/api/user/permissions", nil).WithContext(
				context.WithValue(
					context.Background(),
					middleware.ContextRoles,
					"this is an invalid role",
				),
			),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:        "Request with uncastable non-string roles on context token returns unauthorized",
			authService: &mock_services.MockAuthService{},
			r: httptest.NewRequest("GET", "/api/user/permissions", nil).WithContext(
				context.WithValue(
					context.Background(),
					middleware.ContextRoles,
					5,
				),
			),
			wantStatus: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h := NewAuthHandlers(tt.authService)
			h.GetUserPermissions(rr, tt.r)
			assert.Equal(t, tt.wantStatus, rr.Code, "Expected http response code %d, got %d", tt.wantStatus, rr.Code)
		},
		)
	}
}

package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
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
			wantErr:   NoTokenError,
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
		functionName string
		wantErr      error
	}{
		{
			name: "Valid roles",
			tokenClaims: jwt.MapClaims{
				"roles": []interface{}{"admin"},
			},
			functionName: "tenants",
			wantErr:      nil,
		},
		{
			name: "Invalid roles",
			tokenClaims: jwt.MapClaims{
				"roles": []interface{}{"user"},
			},
			functionName: "tenants",
			wantErr:      InvalidTokenError,
		},
		{
			name: "Empty roles",
			tokenClaims: jwt.MapClaims{
				"roles": []interface{}{},
			},
			functionName: "admin_function",
			wantErr:      InvalidTokenError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tt.tokenClaims,
			}
			err := checkTokenRoles(token, tt.functionName)

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
			wantErr: InvalidTokenError,
		},
		{
			name:    "Invalid token signature",
			token:   jwt.New(jwt.SigningMethodES256),
			wantErr: InvalidTokenError,
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
			},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: InvalidTokenError,
		},
		{
			name: "Token with no token headers",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
			},
			tokenHeaders: map[string]interface{}{},
			wantErr:      InvalidTokenError,
		},
		{
			name: "Token with empty kid header",
			tokenClaims: jwt.MapClaims{
				"iss": "https://invalid.issuer.com",
			},
			tokenHeaders: map[string]interface{}{
				"kid": "",
			},
			wantErr: InvalidTokenError,
		},
		{
			name:        "Token with empty claims",
			tokenClaims: jwt.MapClaims{},
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: InvalidTokenError,
		},
		{
			name:        "Token with no claims",
			tokenClaims: nil,
			tokenHeaders: map[string]interface{}{
				"kid": "b0ffa9ed-7a9f-4d1f-a09d-a81b2a8fb41b",
			},
			wantErr: InvalidTokenError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Claims: tt.tokenClaims,
				Header: tt.tokenHeaders,
			}

			err := validateClaims(token)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Expected error `%v`, got `%v`", tt.wantErr, err)
			}

		})
	}
}

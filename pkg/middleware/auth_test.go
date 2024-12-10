package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func createPrivateTestKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func createValidTestTokenString() string {
	testPrivateKey, err := createPrivateTestKey()
	if err != nil {
		panic(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://app.kriptome.com",
		"tid": "test-tenant-id",
		"sub": "test-user-id",
	})
	tokenString, err := token.SignedString(testPrivateKey)
	if err != nil {
		panic(err)
	}

	return tokenString
}

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

func TestCheckTokenRoles(t *testing.T) {
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

// func Test_parseToken(t *testing.T) {
//
// 	validTokenString := createValidTestTokenString()
// 	// invalidTokenString := createInvalidTokenString()
// 	// invalidSigningMethodTokenString := createInvalidSigningMethodTokenString()
//
// 	// Arrange
// 	testCases := []parseTokenTestCase{
// 		{
// 			name:        "Valid token in Authorization Header",
// 			tokenString: validTokenString,
// 			setupRequest: func(req *http.Request) {
// 				req.Header.Set("Authorization", "Bearer "+validTokenString)
// 			},
// 			expectedError: nil,
// 			expectedValid: true,
// 		},
// 		{
// 			name:        "Token with invalid issuer in Authorization Header",
// 			tokenString: validTokenString,
// 			setupRequest: func(req *http.Request) {
// 				req.Header.Set("Authorization", "Bearer "+validTokenString)
// 			},
// 			expectedError: nil,
// 			expectedValid: false,
// 		},
// 	}
//
// 	for _, tt := range testCases {
// 		t.Run(tt.name, func(t *testing.T) {
// 			req := httptest.NewRequest(http.MethodGet, "/", nil)
// 			if tt.setupRequest != nil {
// 				tt.setupRequest(req)
// 			}
//
// 			token, err := parseToken(req)
// 			if err != nil && tt.expectedError != nil {
// 				if err.Error() != tt.expectedError.Error() {
// 					t.Errorf("Expected error: `%v`, got: `%v`", tt.expectedError, err)
// 				}
// 			} else if err == nil && tt.expectedError != nil {
// 				t.Errorf("Expected error: `%v`, got nil", tt.expectedError)
// 			} else if err != nil && tt.expectedError == nil {
// 				t.Errorf("Expected no error, got: `%v`", err)
// 			}
//
// 			if token != nil && !tt.expectedValid {
// 				t.Errorf("Expected token to be invalid, but it was valid")
// 			} else if token == nil && tt.expectedValid {
// 				t.Errorf("Expected token to be valid, but it was nil")
// 			}
// 		})
// 	}
//
// }

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/kptm-tools/core-service/pkg/api"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/interfaces"
	"github.com/kptm-tools/core-service/pkg/middleware"
	"github.com/kptm-tools/core-service/pkg/services"
)

type AuthHandlers struct {
	authService interfaces.IAuthService
}

var _ interfaces.IAuthHandlers = (*AuthHandlers)(nil)

func NewAuthHandlers(authService interfaces.IAuthService) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
	}
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	loginRequest := new(LoginRequest)

	if err := decodeJSONBody(w, r, loginRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	// Write the response from the service
	resp, err := h.authService.Login(loginRequest.LoginID, loginRequest.Password, loginRequest.ApplicationID)

	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, &resp)

}

func (h *AuthHandlers) RegisterTenant(w http.ResponseWriter, r *http.Request) error {

	registerTenantRequest := new(RegisterTenantRequest)

	if err := decodeJSONBody(w, r, registerTenantRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	t, u, err := h.authService.RegisterTenant(registerTenantRequest.Name)

	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		}
		return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
	}

	return api.WriteJSON(w, http.StatusCreated, &RegisterTenantResponse{ApplicationID: t.ApplicationID, User: *u})
}

func (h *AuthHandlers) GetUser(w http.ResponseWriter, r *http.Request) error {
	id, err := GetUUID(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
	}

	user, err := h.authService.GetUserByID(id.String(), nil)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, user)
}

func (h *AuthHandlers) ForgotPassword(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	forgotPasswordRequest := new(ForgotPasswordRequest)

	if err := decodeJSONBody(w, r, forgotPasswordRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	password, err := h.authService.ForgotPassword(forgotPasswordRequest.LoginID, forgotPasswordRequest.ApplicationID)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, password)
}

func (h *AuthHandlers) RegisterUser(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	registerUserRequest := new(RegisterUserRequest)

	if err := decodeJSONBody(w, r, registerUserRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	user, err := h.authService.RegisterUser(
		registerUserRequest.FirstName,
		registerUserRequest.LastName,
		registerUserRequest.Email,
		registerUserRequest.Password,
		registerUserRequest.ApplicationID,
		registerUserRequest.Roles)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, user)
}

func (h *AuthHandlers) VerifyEmail(w http.ResponseWriter, r *http.Request) error {
	id, err := GetUUID(r)
	tenantID, errTenant := GetTenantIDFromHeader(r)
	if err != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: err.Error()})
	}
	if errTenant != nil {
		return api.WriteJSON(w, http.StatusBadRequest, api.APIError{Error: errTenant.Error()})
	}

	verifyEmailRequest := new(VerifyEmailRequest)

	if err := decodeJSONBody(w, r, verifyEmailRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	user, err := h.authService.VerifyEmail(verifyEmailRequest.VerificationID, id.String(), tenantID)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, user)
}

func (h *AuthHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) error {

	// Fetch parameters
	changePasswordRequest := new(ChangePasswordRequest)

	if err := decodeJSONBody(w, r, changePasswordRequest); err != nil {
		var mr *malformedRequest

		if errors.As(err, &mr) {
			return api.WriteJSON(w, mr.status, api.APIError{Error: mr.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}
	changePassword, err := h.authService.ChangePassword(changePasswordRequest.ChangePasswordID, changePasswordRequest.Password, changePasswordRequest.LoginID, changePasswordRequest.ApplicationID)
	if err != nil {
		var fae *services.FaError

		if errors.As(err, &fae) {
			return api.WriteJSON(w, fae.Status(), api.APIError{Error: fae.Error()})
		} else {
			return api.WriteJSON(w, http.StatusInternalServerError, api.APIError{Error: err.Error()})
		}
	}

	return api.WriteJSON(w, http.StatusOK, changePassword)
}

func WriteUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func WriteInternalServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

func (h *AuthHandlers) WithAuth(endpoint http.HandlerFunc, functionName string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := parseToken(r)
		if err != nil {
			if errors.Is(err, middleware.ErrInvalidToken) {
				slog.Error(err.Error())
				WriteUnauthorized(w)
			} else if errors.Is(err, middleware.ErrNoToken) {
				slog.Error(err.Error())
				WriteUnauthorized(w)
			} else if errors.Is(err, jwt.ErrTokenExpired) {
				slog.Error(err.Error())
				WriteUnauthorized(w)
			} else {
				// General error
				slog.Error("General error: ", err.Error())
				WriteInternalServerError(w)
			}
			return
		}

		// At this point we have the JWT, so we use /golang-jwt/jwt to validate it
		// And then check roles
		if !token.Valid {
			slog.Error("Error validating token: Token is invalid")
			WriteUnauthorized(w)
			return
		}

		// Verify that said user exists
		var tenantID = token.Claims.(jwt.MapClaims)["tid"]
		var userID = token.Claims.(jwt.MapClaims)["sub"]

		exists, err := h.ValidateUserWithFusionAuth(userID.(string), tenantID.(string))
		if err != nil {
			if errors.Is(err, middleware.ErrUserNotFound) {
				slog.Error("User not found", slog.Any("error", err))
				WriteUnauthorized(w)
				return
			} else {
				slog.Error("Error validating user with fusion auth", slog.Any("err", err))
				WriteInternalServerError(w)
				return
			}
		}
		if !exists {
			slog.Error("User is not authorized")
			WriteUnauthorized(w)
			return
		}

		// Verify user roles
		if err := checkTokenRoles(token, functionName); err != nil {
			if errors.Is(err, middleware.ErrInvalidToken) {
				slog.Error("Invalid token", slog.Any("error", err))
				WriteUnauthorized(w)
				return
			}
			slog.Error("General error: ", slog.Any("error", err))
			WriteInternalServerError(w)
			return
		}

		ctx := context.WithValue(r.Context(), middleware.ContextTenantID, tenantID)
		ctx = context.WithValue(ctx, middleware.ContextUserID, userID)
		endpoint(w, r.WithContext(ctx))

	})
}

func parseToken(r *http.Request) (*jwt.Token, error) {
	reqToken, err := getRequestToken(r)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(reqToken, verifyTokenSignature)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func verifyTokenSignature(token *jwt.Token) (interface{}, error) {

	if err := validateSigningMethod(token); err != nil {
		return nil, err
	}
	if err := validateClaims(token); err != nil {
		return nil, err
	}

	// At this point we already validated we have a KID
	kid := token.Header["kid"].(string)
	if err := setPublicKey(kid); err != nil {
		return nil, fmt.Errorf("error setting public key: %w", err)
	}
	return middleware.VerifyKey, nil
}

func validateSigningMethod(token *jwt.Token) error {
	// 1. Check signing method
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		msg := "Invalid signing method"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}
	return nil
}

func validateClaims(token *jwt.Token) error {

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims == nil || len(claims) == 0 {
		msg := "Invalid token claims"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}

	if err := validateIssuer(claims, "https://app.kriptome.com"); err != nil {
		return err
	}
	if err := validateUserAndTenant(claims); err != nil {
		return err
	}
	if err := validateKID(token); err != nil {
		return err
	}
	return nil
}

// verify iss claim: Make sure the issuer is as expected
func validateIssuer(claims jwt.MapClaims, issuer string) error {
	checkIss := claims.VerifyIssuer(issuer, true)
	if !checkIss {
		msg := "Invalid iss"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}
	return nil
}

// Checks if the token header has a "kid" value
func validateKID(token *jwt.Token) error {
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		msg := "Missing kid header"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}
	return nil
}

func validateUserAndTenant(claims jwt.MapClaims) error {
	userID, ok := claims["sub"]
	if !ok || userID == "" {
		msg := "Missing userID claim"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}
	tenantID, ok := claims["tid"]
	if !ok || tenantID == "" {
		msg := "Missing tenantID claim"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}
	return nil
}

// getRequestToken gets the request's token, from either
// the cookie or the header. Returns a [ErrNoToken] on failure
func getRequestToken(r *http.Request) (string, error) {
	reqToken := ""
	tokenCookie, err := r.Cookie("app.at")

	// If token was not in cookie
	if err != nil {
		// If there's no cookie, attempt to extract from header
		if errors.Is(err, http.ErrNoCookie) {
			reqToken = r.Header.Get("Authorization")
			splitToken := strings.Split(reqToken, "Bearer ")

			if len(splitToken) > 1 {
				reqToken = splitToken[1]
			}

		} else {
			// There was a cookie, but there was an error parsing it
			msg := fmt.Sprintf("Error parsing cookie token: `%s`", err.Error())
			return "", fmt.Errorf("%q: %w", msg, middleware.ErrNoToken)
		}
	} else {
		reqToken = tokenCookie.Value
	}

	// If token is empty
	if reqToken == "" {
		msg := "No token provided in cookie or header"
		return "", fmt.Errorf("%q: %w", msg, middleware.ErrNoToken)
	}

	return reqToken, nil
}

func checkTokenRoles(token *jwt.Token, functionName string) error {
	var roles = token.Claims.(jwt.MapClaims)["roles"]
	// Check if we have any roles in our claims
	if len(roles.([]interface{})) == 0 {
		msg := "Token has no roles"
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}

	parsedRoles, err := domain.GetRolesFromStringSlice([]string{roles.([]interface{})[0].(string)})
	if err != nil {
		msg := fmt.Sprintf("Invalid Role: `%s`", err.Error())
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}

	// Check out what page we're calling, so we can check relevant roles
	validRoles, err := domain.GetValidRoles(functionName)
	if err != nil {
		msg := fmt.Sprintf("Invalid Role: `%v`, must be one of `%v`", parsedRoles, validRoles)
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}

	result := domain.ContainsRole(parsedRoles, validRoles)
	// If the length of the intersection is >= 1 , we have the proper role
	// log.Printf("Intersection result: `%v`\n", result)
	if len(result) == 0 {
		msg := fmt.Sprintf("Roles missing: Have `%v`, want one of `%v`", parsedRoles, validRoles)
		return fmt.Errorf("%q: %w", msg, middleware.ErrInvalidToken)
	}

	return nil
}

func setPublicKey(kid string) error {
	c := config.LoadConfig()
	// Retrieves the public key for JWT from FusionAuth
	if middleware.VerifyKey == nil {
		url := fmt.Sprintf("http://%s:%s/api/jwt/public-key?kid=%s", c.FusionAuthHost, c.FusionAuthPort, kid)
		response, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("problem connecting to FusionAuth: `%s`", err.Error())
		}

		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("problem reading FusionAuth response: `%s`", err.Error())
		}

		var publicKey map[string]interface{}

		if err = json.Unmarshal(responseData, &publicKey); err != nil {
			return fmt.Errorf("problem unmarshaling response: `%s`", err.Error())
		}

		var publicKeyPEM = publicKey["publicKey"].(string)

		var verifyBytes = []byte(publicKeyPEM)
		middleware.VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

		if err != nil {
			return fmt.Errorf("problem retreiving public key: `%s`", err.Error())
		}
	}
	return nil
}

func (h *AuthHandlers) ValidateUserWithFusionAuth(userID, tenantID string) (bool, error) {

	_, err := h.authService.GetUserByID(userID, &tenantID)
	if err != nil {
		var faErr *services.FaError
		if errors.As(err, &faErr) {
			msg := faErr.Error()
			slog.Error("FusionAuth error fetching user", slog.String("error", faErr.Error()))
			return false, fmt.Errorf("%q: %w", msg, middleware.ErrUserNotFound)

		} else {
			slog.Error("Error fetching user", slog.String("error", err.Error()))
			return false, err
		}
	}

	return true, nil
}

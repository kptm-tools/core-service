package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"github.com/kptm-tools/core-service/pkg/services"
	"github.com/kptm-tools/core-service/pkg/storage"
)

type InvalidTokenError struct {
	msg string
}

func (e *InvalidTokenError) Error() string {
	return e.msg
}

func NewInvalidTokenError(msg string) error {
	return &InvalidTokenError{msg}
}

var NoTokenError = errors.New("Token not found")

type UserNotFoundError struct {
	msg string
}

func (e *UserNotFoundError) Error() string {
	return e.msg
}

func NewUserNotFoundError(msg string) error {
	return &UserNotFoundError{msg}
}

var verifyKey *rsa.PublicKey

type ContextKey string

const ContextTenantID ContextKey = "tenantID"

func WriteUnauthorized(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func WriteInternalServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

func WithAuth(endpoint http.HandlerFunc, functionName string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := parseToken(r)
		if err != nil {
			var invalidTokenErr *InvalidTokenError
			if errors.As(err, &invalidTokenErr) {
				log.Println("Error validating token: ", invalidTokenErr.Error())
				WriteUnauthorized(w)
				return
			} else {
				// General error
				log.Println("General error: ", err.Error())
				WriteInternalServerError(w)
				return
			}
		}

		// At this point we have the JWT, so we use /golang-jwt/jwt to validate it
		// And then check roles
		if !token.Valid {
			log.Printf("Error validating token: `Invalid token`\n")
			WriteUnauthorized(w)
			return
		}

		// Verify that said user exists
		var tenantID = token.Claims.(jwt.MapClaims)["tid"]
		var userID = token.Claims.(jwt.MapClaims)["sub"]

		exists, err := validateUserWithFusionAuth(userID.(string), tenantID.(string))
		if err != nil {
			var userNotFoundError *UserNotFoundError
			if errors.As(err, &userNotFoundError) {
				log.Println("UserNotFoundError: ", userNotFoundError.Error())
				WriteUnauthorized(w)
				return
			} else {
				log.Println("Error validating user: ", err.Error())
				WriteInternalServerError(w)
				return
			}
		}
		if !exists {
			log.Printf("User is not registered\n")
			WriteUnauthorized(w)
			return
		}

		// Verify user roles
		if err := checkTokenRoles(token, functionName); err != nil {
			var invalidTokenErr *InvalidTokenError
			if errors.As(err, &invalidTokenErr) {
				log.Printf("Error validating token: `%+v`\n", err)
				WriteUnauthorized(w)
				return
			}
			log.Println("General error: ", err.Error())
			WriteInternalServerError(w)
			return
		}

		ctx := context.WithValue(r.Context(), ContextTenantID, tenantID)
		endpoint(w, r.WithContext(ctx))

	})
}

func parseToken(r *http.Request) (*jwt.Token, error) {

	reqToken, err := getRequestToken(r)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
		// 1. Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			msg := "Invalid signing method"
			return nil, NewInvalidTokenError(msg)
		}

		// 2. Check aud: make sure the token is intended for this application

		/*aud := config.LoadConfig().ApplicationID
		checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)

		if !checkAudience {
			return nil, fmt.Errorf("Invalid audience")
		}
		*/

		// verify iss claim: Make sure the issuer is as expected
		iss := "https://app.kriptome.com" // TODO: Set this to env var
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			msg := "Invalid iss"
			return nil, NewInvalidTokenError(msg)
		}

		if err := setPublicKey(token.Header["kid"].(string)); err != nil {
			return nil, fmt.Errorf("Error setting public key")
		}

		return verifyKey, nil
	})
	if err != nil {
		msg := fmt.Sprintf("Error parsing token: %v", err)
		return nil, NewInvalidTokenError(msg)
	}

	return token, nil
}

// getRequestToken gets the request's token, from either
// the cookie or the header. Returns a [NoTokenError] on failure
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
			return "", fmt.Errorf("%s: %w", msg, NoTokenError)
		}
	} else {
		reqToken = tokenCookie.Value
	}

	// If token is empty
	if reqToken == "" {
		msg := "No token provided in cookie or header"
		return "", fmt.Errorf("%s: %w", msg, NoTokenError)
	}

	return reqToken, nil
}

func checkTokenRoles(token *jwt.Token, functionName string) error {
	var roles = token.Claims.(jwt.MapClaims)["roles"]
	parsedRoles, err := domain.GetRolesFromStringSlice([]string{roles.([]interface{})[0].(string)})

	if err != nil {
		msg := fmt.Sprintf("Invalid Role: `%s`", err.Error())
		return NewInvalidTokenError(msg)
	}

	// Check out what page we're calling, so we can check relevant roles
	validRoles, err := domain.GetValidRoles(functionName)
	if err != nil {
		msg := fmt.Sprintf("Invalid Role: `%v`, must be one of `%v`", parsedRoles, validRoles)
		return NewInvalidTokenError(msg)
	}

	result := domain.ContainsRole(parsedRoles, validRoles)
	// If the length of the intersection is >= 1 , we have the proper role
	// log.Printf("Intersection result: `%v`\n", result)
	if len(result) == 0 {
		msg := fmt.Sprintf("Roles missing: Have `%v`, want one of `%v`", parsedRoles, validRoles)
		return NewInvalidTokenError(msg)
	}

	return nil
}

func setPublicKey(kid string) error {
	c := config.LoadConfig()
	// Retrieves the public key for JWT from FusionAuth
	if verifyKey == nil {
		url := fmt.Sprintf("http://%s:%s/api/jwt/public-key?kid=%s", c.FusionAuthHost, c.FusionAuthPort, kid)
		response, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("Problem connecting to FusionAuth: `%s`", err.Error())
		}

		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("Problem reading FusionAuth response: `%s`", err.Error())
		}

		var publicKey map[string]interface{}

		if err = json.Unmarshal(responseData, &publicKey); err != nil {
			return fmt.Errorf("Problem unmarshaling response: `%s`", err.Error())
		}

		var publicKeyPEM = publicKey["publicKey"].(string)

		var verifyBytes = []byte(publicKeyPEM)
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

		if err != nil {
			return fmt.Errorf("Problem retreiving public key: `%s`", err.Error())
		}
	}
	return nil
}

func validateUserWithFusionAuth(userID, tenantID string) (bool, error) {
	c := config.LoadConfig()
	storage, _ := storage.NewPostgreSQLStore(c.PostgreSQLCoreConnStr())
	authService := services.NewAuthService(storage)

	_, err := authService.GetUserByID(userID, &tenantID)
	if err != nil {
		var faErr *services.FaError
		if errors.As(err, &faErr) {
			msg := faErr.Error()
			log.Printf("FusionAuth error fetching user: `%s`", msg)
			return false, NewUserNotFoundError(msg)

		} else {
			log.Printf("Error fetching user: `%s`\n", err.Error())
			return false, err
		}
	}

	return true, nil
}

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

var InvalidTokenError = errors.New("Invalid token")

var NoTokenError = errors.New("Token not found")

var UserNotFoundError = errors.New("User not found")

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
			if errors.Is(err, InvalidTokenError) {
				log.Println(err.Error())
				WriteUnauthorized(w)
				return
			} else if errors.Is(err, NoTokenError) {
				log.Println(err.Error())
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
			if errors.Is(err, UserNotFoundError) {
				log.Println(err.Error())
				WriteUnauthorized(w)
				return
			} else {
				log.Println(err.Error())
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
			if errors.Is(err, InvalidTokenError) {
				log.Printf(err.Error())
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
		return nil, fmt.Errorf("Error setting public key")
	}
	return nil, nil
}

func validateSigningMethod(token *jwt.Token) error {
	// 1. Check signing method
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		msg := "Invalid signing method"
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}
	return nil
}

func validateClaims(token *jwt.Token) error {

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims == nil || len(claims) == 0 {
		msg := "Invalid token claims"
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
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
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}
	return nil
}

// Checks if the token header has a "kid" value
func validateKID(token *jwt.Token) error {
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		msg := "Missing kid header"
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}
	return nil
}

func validateUserAndTenant(claims jwt.MapClaims) error {
	userID, ok := claims["sub"]
	if !ok || userID == "" {
		msg := "Missing userID claim"
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}
	tenantID, ok := claims["tid"]
	if !ok || tenantID == "" {
		msg := "Missing tenantID claim"
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}
	return nil
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
			return "", fmt.Errorf("%q: %w", msg, NoTokenError)
		}
	} else {
		reqToken = tokenCookie.Value
	}

	// If token is empty
	if reqToken == "" {
		msg := "No token provided in cookie or header"
		return "", fmt.Errorf("%q: %w", msg, NoTokenError)
	}

	return reqToken, nil
}

func checkTokenRoles(token *jwt.Token, functionName string) error {
	var roles = token.Claims.(jwt.MapClaims)["roles"]
	// Check if we have any roles in our claims
	if len(roles.([]interface{})) == 0 {
		msg := "Token has no roles"
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}

	parsedRoles, err := domain.GetRolesFromStringSlice([]string{roles.([]interface{})[0].(string)})
	if err != nil {
		msg := fmt.Sprintf("Invalid Role: `%s`", err.Error())
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}

	// Check out what page we're calling, so we can check relevant roles
	validRoles, err := domain.GetValidRoles(functionName)
	if err != nil {
		msg := fmt.Sprintf("Invalid Role: `%v`, must be one of `%v`", parsedRoles, validRoles)
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
	}

	result := domain.ContainsRole(parsedRoles, validRoles)
	// If the length of the intersection is >= 1 , we have the proper role
	// log.Printf("Intersection result: `%v`\n", result)
	if len(result) == 0 {
		msg := fmt.Sprintf("Roles missing: Have `%v`, want one of `%v`", parsedRoles, validRoles)
		return fmt.Errorf("%q: %w", msg, InvalidTokenError)
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
			return false, fmt.Errorf("%q: %w", msg, UserNotFoundError)

		} else {
			log.Printf("Error fetching user: `%s`\n", err.Error())
			return false, err
		}
	}

	return true, nil
}

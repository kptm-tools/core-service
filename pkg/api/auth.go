package api

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

var verifyKey *rsa.PublicKey

type ContextKey string

const ContextTenantID ContextKey = "tenantID"

func WithAuth(endpoint http.HandlerFunc, functionName string) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqToken := ""
		tokenCookie, err := r.Cookie("app.at")

		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				reqToken = r.Header.Get("Authorization")
				splitToken := strings.Split(reqToken, "Bearer ")

				if len(splitToken) > 1 {
					reqToken = splitToken[1]
				}
			} else {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: err.Error()})
				return
			}
		} else {
			reqToken = tokenCookie.Value

		}

		if reqToken == "" {
			WriteJSON(w, http.StatusUnauthorized, APIError{Error: "No token provided"})
			return
		} else {
			token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
				// 1. Check signing method
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Invalid signing method")
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
					return nil, fmt.Errorf(("invalid iss"))
				}

				if err := setPublicKey(token.Header["kid"].(string)); err != nil {
					return nil, fmt.Errorf("Error setting public key")
				}

				return verifyKey, nil
			})

			if err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: err.Error()})
				return
			}

			// At this point we have the JWT, so we use /golang-jwt/jwt to validate it
			// And then check roles

			if !token.Valid {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid token"})
				return
			}
			var tenantID = token.Claims.(jwt.MapClaims)["tid"]
			var userID = token.Claims.(jwt.MapClaims)["sub"]

			// Verify that said user exists
			exists, err := validateUserWithFusionAuth(userID.(string), tenantID.(string))
			if !exists {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "User is not registered"})
				return
			}

			var roles = token.Claims.(jwt.MapClaims)["roles"]
			parsedRoles, err := domain.GetRolesFromStringSlice([]string{roles.([]interface{})[0].(string)})

			if err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid Role"})
				return
			}

			// Check out what page we're calling, so we can check relevant roles
			validRoles, err := domain.GetValidRoles(functionName)

			if err != nil {
				log.Println(err)
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Roles missing"})
				return
			}

			result := domain.ContainsRole(parsedRoles, validRoles)

			// If the length of the intersection is >= 1 , we have the proper role
			// log.Printf("Intersection result: `%v`\n", result)
			if len(result) == 0 {

				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid role"})
				return
			}
			ctx := context.WithValue(r.Context(), ContextTenantID, tenantID)
			endpoint(w, r.WithContext(ctx))

		}
	})
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
		log.Printf("Error fetching user: `%s`\n", err.Error())
		return false, err
	}

	return true, nil
}

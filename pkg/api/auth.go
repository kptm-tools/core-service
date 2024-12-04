package api

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/kptm-tools/core-service/pkg/config"
	"github.com/kptm-tools/core-service/pkg/domain"
	"io"
	"log"
	"net/http"
	"strings"
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
				iss := "https://piedpipervideochat.com" // TODO: Set this to env var
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !checkIss {
					return nil, fmt.Errorf(("invalid iss"))
				}

				setPublicKey(token.Header["kid"].(string))
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

			}
			var tenantID = token.Claims.(jwt.MapClaims)["tid"]
			log.Print(tenantID)
			var userID = token.Claims.(jwt.MapClaims)["sub"]
			log.Print(userID)
			// Build request
			req, err := buildFusionAuthVerifyRequest(tenantID.(string), userID.(string))

			if err != nil {
				fmt.Errorf("Invalid request build")
				return
			}
			// Send request
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Not able to verify with AuthProvider"})
			}
			log.Print(resp)

			var roles = token.Claims.(jwt.MapClaims)["roles"]
			parsedRoles, err := domain.GetRolesFromStringSlice([]string{roles.([]interface{})[0].(string)})

			if err != nil {
				WriteJSON(w, http.StatusUnauthorized, APIError{Error: "Invalid Role"})
			}

			// Check out what page we're calling, so we can check relevant roles
			validRoles, err := domain.GetValidRoles(functionName)

			if err != nil {
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

func setPublicKey(kid string) {
	c := config.LoadConfig()
	// Retrieves the public key for JWT from FusionAuth
	if verifyKey == nil {
		// TODO: Change with env var for FusionAuth host
		url := fmt.Sprintf("http://%s:%s/api/jwt/public-key?kid=%s", c.FusionAuthHost, c.FusionAuthPort, kid)
		response, err := http.Get(url)
		if err != nil {
			log.Fatalln(err)
		}

		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}

		var publicKey map[string]interface{}

		json.Unmarshal(responseData, &publicKey)

		var publicKeyPEM = publicKey["publicKey"].(string)

		var verifyBytes = []byte(publicKeyPEM)
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

		if err != nil {
			log.Fatalln(("problem retreiving public key"))
		}
	}
}

func buildFusionAuthVerifyRequest(tenantID string, userID string) (*http.Request, error) {
	c := config.LoadConfig()
	apiKey := c.FusionAuthAPIKey
	url := fmt.Sprintf("http://%s:%s/api/user/%s", c.FusionAuthHost, c.FusionAuthPort, userID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("X-FusionAuth-TenantId", tenantID)
	return req, nil
}

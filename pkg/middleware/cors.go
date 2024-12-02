package middleware

import (
	"net/http"
	"slices"
	"strings"

	"github.com/kptm-tools/core-service/pkg/config"
)

var originAllowlist = config.LoadConfig().GetAllowedOrigins()
var methodAllowlist = []string{"GET", "POST", "DELETE", "OPTIONS"}
var allowedHeaders = []string{"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token", "Authorization"}

func CheckCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if isPreflight(r) {
			origin := r.Header.Get("Origin")
			method := r.Header.Get("Access-Control-Request-Method")
			if slices.Contains(originAllowlist, origin) && slices.Contains(methodAllowlist, method) {
				// Preflight request (OPTIONS)
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(methodAllowlist, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
				w.Header().Set("Allow", strings.Join(methodAllowlist, ", "))
				w.WriteHeader(http.StatusNoContent) // Write the status
				return
			}
		} else {
			// Not a preflight: regular request
			origin := r.Header.Get("Origin")
			if slices.Contains(originAllowlist, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
		}
		w.Header().Add("Vary", "Origin")
		next.ServeHTTP(w, r)
	})
}

func isPreflight(r *http.Request) bool {
	return r.Method == "OPTIONS" &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

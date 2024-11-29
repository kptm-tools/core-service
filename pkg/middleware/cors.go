package middleware

import (
	"net/http"
	"slices"
	"strings"

	"github.com/kptm-tools/core-service/pkg/config"
)

var originAllowlist = config.LoadConfig().GetAllowedOrigins()
var methodAllowlist = []string{"GET", "POST", "DELETE", "OPTIONS"}

func CheckCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		origin := r.Header.Get("Origin")
		method := r.Header.Get("Access-Control-Request-Method")

		if slices.Contains(originAllowlist, origin) && slices.Contains(methodAllowlist, method) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(methodAllowlist, ", "))
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

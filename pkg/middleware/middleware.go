package middleware

import "net/http"

type Middleware func(http.Handler) http.Handler

// To create a middleware stack and avoid ugly nesting in our api code
func CreateStack(xs ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(xs) - 1; i >= 0; i-- {
			x := xs[i]
			next = x(next)
		}

		return next
	}

}

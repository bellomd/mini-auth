package jwtauth

import (
	"net/http"
	"os"

	"github.com/bellomd/miniauth/auth/authenv"
)

// DoFilter check if the request has the requeired permission
func DoFilter(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get(os.Getenv(authenv.AuthorizationHeaderKey))
		if authHeader == "" {
			http.Error(w, "invalid token", http.StatusForbidden)
			return
		}
		if !IsValidDefault(authHeader) {
			http.Error(w, "invalid token", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

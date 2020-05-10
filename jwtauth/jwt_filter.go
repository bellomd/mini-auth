package jwtauth

import (
	"net/http"
	"os"

	miniauth "github.com/bellomnk/mini-auth"
)

// DoFilter check if the request is allowed to permission for the
// requested service.
func DoFilter(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get(os.Getenv(miniauth.AuthorizationHeaderKey))
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

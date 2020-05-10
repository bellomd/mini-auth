package miniauth

import (
	"log"
	"math/rand"
	"os"
)

// RandStr generate a random string of the given size.
func RandStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = Alphabets[rand.Int63()%int64(len(Alphabets))]
	}
	return string(b)
}

// LoadEnvironmentVariables import and set os default environment variables
func LoadEnvironmentVariables() {
	tokenKey := os.Getenv(TokenEnvKey)
	if tokenKey == "" {
		err := os.Setenv(TokenEnvKey, RandStr(KeyByteSize))
		if err != nil {
			log.Panicf("unable to set default token key ->> %s", err)
		}
	}
	signingMethod := os.Getenv(SigningMethodEnvKey)
	if signingMethod == "" {
		err := os.Setenv(SigningMethodEnvKey, SigningMethod)
		if err != nil {
			log.Panicf("unable to set default signing method ->> %s", err)
		}
	}
	authorizationHeader := os.Getenv(AuthorizationHeaderKey)
	if authorizationHeader == "" {
		err := os.Setenv(AuthorizationHeaderKey, AuthorizationHeader)
		if err != nil {
			log.Panicf("unable to set default authorization header ->> %s", err)
		}
	}
	tokenExpirationTime := os.Getenv(TokenExpirationKey)
	if tokenExpirationTime == "" {
		err := os.Setenv(TokenExpirationKey, string(ExpirationTime))
		if err != nil {
			log.Panicf("unable to set default authorization header ->> %s", err)
		}
	}
}

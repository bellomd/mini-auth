package authenv

import "time"

// DefaultExpirationTime for expiration time
var DefaultExpirationTime = time.Now().Add(24 * time.Hour)

const (
	// TokenEnvKey as key
	TokenEnvKey = "DefaultTokenKey"
	// SigningMethodEnvKey as key
	SigningMethodEnvKey = "DefaultSigningMethod"
	// SigningMethod as key
	SigningMethod = "HS512"
	// KeyByteSize default key size
	KeyByteSize = 512
	// AuthorizationHeaderKey for auth header key
	AuthorizationHeaderKey = "AuthorizationHeaderKey"
	// AuthorizationHeader for auth header
	AuthorizationHeader = "Authorization"
	// TokenExpirationKey for expiration time
	TokenExpirationKey = "ExpirationTime"
	// ExpirationTime as token expiration
	ExpirationTime = (60 * 60 * 24) // in seconds
	// Alphabets that are used for generating default key
	Alphabets = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#%^&*()_+|?><~1234567890"
)

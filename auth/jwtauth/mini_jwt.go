package jwtauth

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bellomd/miniauth/auth/authenv"
	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// MiniClaims as claim for jwt
type MiniClaims struct {
	Data jwt.MapClaims
	jwt.StandardClaims
}

// The init function try to check all required properties from the environment
// variables, if they found then they will be used other, it set defaults.
// If you don't want to use the generated once you can always reset them
// in the os environment.
func init() {
	authenv.LoadEnvironmentVariables()
}

// Generate with the given key, claims and signing method
func Generate(signingMethod string, claims jwt.Claims, tokenKey []byte) (token string, err error) {
	if claims == nil {
		return "", errors.New("invalid claims")
	}
	if signingMethod == "" {
		return "", errors.New("invalid signing method")
	}
	if string(tokenKey) == "" {
		return "", errors.New("invalid key")
	}
	return generateToken(jwt.GetSigningMethod(signingMethod), claims, tokenKey)
}

func generateToken(signingMethod jwt.SigningMethod, claims jwt.Claims, tokenKey []byte) (token string, err error) {
	generatedToken := jwt.NewWithClaims(signingMethod, claims)
	tokenString, err := generatedToken.SignedString(tokenKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// GenerateWithDefault generate with the signing method and key that was
// set in the os environment variables, refer to init(...) above on
// what and how the environment variables are set.
func GenerateWithDefault(claims jwt.Claims) (token string, err error) {
	if claims == nil {
		return "", errors.New("invalid claims")
	}
	signingMethod := jwt.GetSigningMethod(os.Getenv(authenv.SigningMethodEnvKey))
	generatedToken := jwt.NewWithClaims(signingMethod, claims)
	tokenKey := os.Getenv(authenv.TokenEnvKey)
	tokenString, err := generatedToken.SignedString([]byte(tokenKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// ParseToken parse the given header value to a claim using the given key
func ParseToken(headerValue string, tokenKey []byte) (claims jwt.Claims, err error) {
	headerToken := headerValue[7:]
	parseToken, err := jwt.Parse(headerToken, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		log.Printf("error parsing token ->> %s", err)
		return nil, err
	}
	if !parseToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return parseToken.Claims, nil
}

// ParseTokenWithClaims parse the given header value to the given claim using the given key
func ParseTokenWithClaims(headerValue string, claims jwt.Claims, tokenKey []byte) (err error) {
	headerToken := headerValue[7:]
	parseToken, err := jwt.ParseWithClaims(headerToken, claims, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		log.Printf("error parsing token ->> %s", err)
		return err
	}
	if !parseToken.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

// ParseTokenDefault parse the given header value to a claim using the key in the os env.
func ParseTokenDefault(headerValue string) (claims jwt.Claims, err error) {
	headerToken := headerValue[7:]
	tokenKey := []byte(os.Getenv(authenv.TokenEnvKey))
	parseToken, err := jwt.Parse(headerToken, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		log.Printf("error parsing token ->> %s", err)
		return nil, err
	}
	if !parseToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return parseToken.Claims, nil
}

// ParseTokenWithClaimsDefault parse the given header value to the given claim using the key in the os env.
func ParseTokenWithClaimsDefault(headerValue string, claims jwt.Claims) (err error) {
	headerToken := headerValue[7:]
	tokenKey := []byte(os.Getenv(authenv.TokenEnvKey))
	parseToken, err := jwt.ParseWithClaims(headerToken, claims, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		log.Printf("error parsing token ->> %s", err)
		return err
	}
	if !parseToken.Valid {
		return fmt.Errorf("invalid token")
	}
	return nil
}

// RefreshToken reset the given token expiration time for the given key to future time
func RefreshToken(token string, tokenKey []byte) (newToken string, err error) {
	pureToken := token[7:]
	parseToken, err := jwt.Parse(pureToken, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		return "", err
	}
	if !parseToken.Valid {
		return "", fmt.Errorf("invalid token")
	}

	// Unless the token is about to expire before renewing it, otherwise,
	// just return the token to user, to avoid unnecessary creation of token.
	mapClaims := parseToken.Claims.(jwt.MapClaims)
	expirationTime := int64(mapClaims["exp"].(float64))
	if time.Until(time.Unix(expirationTime, 0)) > 1*time.Hour {
		return pureToken, nil
	}

	// The token is about to expire, creat a new token for the user
	mapClaims["exp"] = authenv.DefaultExpirationTime.Unix() // reset the expiration time
	parseToken.Claims = mapClaims                           // assign the claims back
	tokenString, err := parseToken.SignedString(tokenKey)   // generate new token
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// RefreshWithDefault reset the given token expiration time for the given key to future time
func RefreshWithDefault(token string) (newToken string, err error) {
	pureToken := token[7:]
	tokenKeyStr := os.Getenv(authenv.TokenEnvKey)
	if tokenKeyStr == "" {
		return "", fmt.Errorf("invalid key")
	}
	tokenKey := []byte(tokenKeyStr)
	parseToken, err := jwt.Parse(pureToken, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		return "", err
	}
	if !parseToken.Valid {
		return "", fmt.Errorf("invalid token")
	}

	// Unless the token is about to expire before renewing it, otherwise,
	// just return the token to user, to avoid unnecessary creation of token.
	mapClaims := parseToken.Claims.(jwt.MapClaims)
	expirationTime := int64(mapClaims["exp"].(float64))
	if time.Until(time.Unix(expirationTime, 0)) > 1*time.Hour {
		return pureToken, nil
	}

	// The token is about to expire, creat a new token for the user
	mapClaims["exp"] = authenv.DefaultExpirationTime.Unix() // reset the expiration time
	parseToken.Claims = mapClaims                           // assign the claims back
	tokenString, err := parseToken.SignedString(tokenKey)   // generate new token
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// IsValid checks if the given token is a valid token
func IsValid(token string, tokenKey []byte) bool {
	pureToken := token[7:]
	parseToken, err := jwt.Parse(pureToken, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		log.Printf("error parsing token ->> %s", err)
		return false
	}
	return parseToken.Valid
}

// IsValidDefault checks if the given token is a valid token with the key in os env.
func IsValidDefault(token string) bool {
	pureToken := token[7:]
	tokenKeyStr := os.Getenv(authenv.TokenEnvKey)
	if tokenKeyStr == "" {
		log.Println("invalid key")
		return false
	}
	tokenKey := []byte(tokenKeyStr)
	parseToken, err := jwt.Parse(pureToken, func(parseToken *jwt.Token) (interface{}, error) {
		return tokenKey, nil
	})
	if err != nil {
		log.Printf("error parsing token ->> %s", err)
		return false
	}
	return parseToken.Valid
}

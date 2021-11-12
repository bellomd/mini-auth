package jwta

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bellomd/miniauth/auth"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var tokenKey = []byte("ufjNxFU+K_#&HVu8!Y+kG?9cePD@rh!jCFN$wMcjQG2NSq&xZmYcE9zXW7aZpsmKKzC%MW7--3ruH6bhH*ccvbmY6=Jq6c7w$!Vy?rN!CufDr8vKA^4eYAFjxZK__9tsa+T9FRK#vpNPg8WYmnB=bTTKbYVYwn#DF8uj+37NFvuMF5GWvpK==ayg_+G5*dKaBQ?6+rad#uXN??EJSX_LLQjAg7@-M^D$HTDFutJDHt!k44AG5Q9rMyrFzdBHN5a4A#S7x^2Fy5YbJe=Y4*j_uvA+U7W*kNFD$yyxfTWqF-^+@m9KSZ5aQbacb5TuB+dN8M@b_uf=pwCqHtMy!PmH%k=Ef=Shhsy6SnpJqqqnVn^3N-3EmC#9YadH+-+J*E_y-uN6J9+V5yBw6jyN!MJTC%juP5GNEdfF9GuPd%=MVp8Byrk7cpPm7G8=^bM4Ek4s2tr%nB$WdZ&W$@z@C=sWdFDnnYg^YarfJzTv_tHKS447qVfQN-#jVC@hYdb?CMHJ")

func TestNewToken(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}
}

func TestNewTokenWithInvalidClaim(t *testing.T) {
	signingKey := "HS512"
	token, err := Generate(signingKey, nil, tokenKey)

	if err == nil {
		t.Fatalf("expected error but not returned ->> %s", err)
	}
	if err.Error() != "invalid claims" {
		t.Fatalf(`expected "invalid claims" but %s is returned as error`, err)
	}
	if len(strings.TrimSpace(token)) > 0 {
		t.Fatalf("expected 0 length token but %s is returned", token)
	}
}

func TestTokenWithDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}
}

func TestTokenWithDefaultWithInvalidClaim(t *testing.T) {
	token, err := GenerateWithDefault(nil)
	if err == nil {
		t.Fatalf("expected error but not returned ->> %s", err)
	}
	if err.Error() != "invalid claims" {
		t.Fatalf(`expected "invalid claims" but %s is returned as error`, err)
	}
	if len(strings.TrimSpace(token)) > 0 {
		t.Fatalf("expected 0 length token but %s is returned", token)
	}
}

func TestParseToken(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Parse the generated token for MiniClaim
	parsedClaims, err := ParseToken(fmt.Sprintf("Bearer %s", token), tokenKey)
	if err != nil {
		t.Fatalf("error passing token for mini claim ->> %s", err)
	}
	parsedClaimsData := parsedClaims.(jwt.MapClaims)["Data"].(map[string]interface{})
	if !strings.EqualFold(miniClaims.Data["uid"].(string), parsedClaimsData["uid"].(string)) {
		t.Fatalf("\n expected ->> %v\n foundiii ->> %v \n", miniClaims.Data, parsedClaimsData)
	}
}

func TestParseTokenWithClaims(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Parse the generated token for MiniClaim
	parsedClaims := &MiniClaims{}
	err = ParseTokenWithClaims(fmt.Sprintf("Bearer %s", token), parsedClaims, tokenKey)
	if err != nil {
		t.Fatalf("error passing token for mini claim ->> %s", err)
	}
	//parsedClaimsData := parsedClaims.(jwt.MapClaims)["Data"].(map[string]interface{})
	if !reflect.DeepEqual(miniClaims, parsedClaims) {
		t.Fatalf("\n expected ->> %v\n foundiii ->> %v \n", miniClaims, parsedClaims)
	}
}

func TestParseTokenDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Parse the generated token for MiniClaim
	parsedClaims, err := ParseTokenDefault(fmt.Sprintf("Bearer %s", token))
	if err != nil {
		t.Fatalf("error passing token for mini claim ->> %s", err)
	}
	parsedClaimsData := parsedClaims.(jwt.MapClaims)["Data"].(map[string]interface{})
	if !strings.EqualFold(miniClaims.Data["uid"].(string), parsedClaimsData["uid"].(string)) {
		t.Fatalf("\n expected ->> %v\n foundiii ->> %v \n", miniClaims.Data, parsedClaimsData)
	}
}

func TestParseTokenWithClaimsDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Parse the generated token for MiniClaim
	parsedClaims := &MiniClaims{}
	err = ParseTokenWithClaimsDefault(fmt.Sprintf("Bearer %s", token), parsedClaims)
	if err != nil {
		t.Fatalf("error passing token for mini claim ->> %s", err)
	}
	//parsedClaimsData := parsedClaims.(jwt.MapClaims)["Data"].(map[string]interface{})
	if !reflect.DeepEqual(miniClaims, parsedClaims) {
		t.Fatalf("\n expected ->> %v\n foundiii ->> %v \n", miniClaims, parsedClaims)
	}
}

func TestRefreshToken(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(1 * time.Minute).Unix() // change the default expiration time to a minute
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	refreshedToken, err := RefreshToken(fmt.Sprintf("Bearer %s", token), tokenKey)
	if err != nil {
		t.Fatalf("error refreshing token ->> %s", err)
	}
	if refreshedToken == "" {
		t.Fatalf(`expected a valid token but "%s" was found`, err)
	}

	newClaims := &MiniClaims{}
	ParseTokenWithClaims(fmt.Sprintf("Bearer %s", refreshedToken), newClaims, tokenKey)
	if reflect.DeepEqual(miniClaims, newClaims) {
		t.Fatal(`expected different claim but found same claim`)
	}
}

func TestRefreshWithExpiredToken(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(-10 * time.Minute).Unix() // set previous time
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s\n", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated\n")
	}

	// Refresh the generated token
	refreshedToken, err := RefreshToken(fmt.Sprintf("Bearer %s", token), tokenKey)
	if err == nil {
		t.Fatal("expected error but token was generated\n")
	}
	if len(refreshedToken) > 0 {
		t.Fatalf(`expected empty found "%s\n"`, refreshedToken)
	}
	if err.Error() != "Token is expired" {
		t.Fatalf(`expected "Token is expired" found "%s"\n`, err)
	}

}

func TestRefreshWithValidToken(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(2 * time.Hour).Unix() // set the expiration time to 2 hours
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	refreshedToken, err := RefreshToken(fmt.Sprintf("Bearer %s", token), tokenKey)
	if err != nil {
		t.Fatalf("error refreshing token ->> %s", err)
	}
	if refreshedToken == "" {
		t.Fatalf(`expected a valid token but "%s" was found`, err)
	}

	if !reflect.DeepEqual(token, refreshedToken) {
		t.Fatalf(`expected ->> "%s" found ->> "%s"`, token, refreshedToken)
	}
}

func TestRefreshTokenDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(1 * time.Minute).Unix() // change the default expiration time to a minute
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	refreshedToken, err := RefreshWithDefault(fmt.Sprintf("Bearer %s", token))
	if err != nil {
		t.Fatalf("error refreshing token ->> %s", err)
	}
	if refreshedToken == "" {
		t.Fatalf(`expected a valid token but "%s" was found`, err)
	}

	newClaims := &MiniClaims{}
	ParseTokenWithClaimsDefault(fmt.Sprintf("Bearer %s", refreshedToken), newClaims)
	if reflect.DeepEqual(miniClaims, newClaims) {
		t.Fatal(`expected different claim but found same claim`)
	}
}

func TestRefreshWithExpiredTokenDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(-10 * time.Minute).Unix() // set previous time
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s\n", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated\n")
	}

	// Refresh the generated token
	refreshedToken, err := RefreshWithDefault(fmt.Sprintf("Bearer %s", token))
	if err == nil {
		t.Fatal("expected error but token was generated\n")
	}
	if len(refreshedToken) > 0 {
		t.Fatalf(`expected empty found "%s\n"`, refreshedToken)
	}
	if err.Error() != "Token is expired" {
		t.Fatalf(`expected "Token is expired" found "%s"\n`, err)
	}

}

func TestRefreshWithValidTokenDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(2 * time.Hour).Unix() // set the expiration time to 2 hours
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	refreshedToken, err := RefreshWithDefault(fmt.Sprintf("Bearer %s", token))
	if err != nil {
		t.Fatalf("error refreshing token ->> %s", err)
	}
	if refreshedToken == "" {
		t.Fatalf(`expected a valid token but "%s" was found`, err)
	}

	if !reflect.DeepEqual(token, refreshedToken) {
		t.Fatalf(`expected ->> "%s" found ->> "%s"`, token, refreshedToken)
	}
}

func TestIsValid(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(2 * time.Hour).Unix() // set the expiration time to 2 hours
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	valid := IsValid(fmt.Sprintf("Bearer %s", token), tokenKey)
	if !valid {
		t.Fatalf("expected true found %v", valid)
	}
}

func TestIsValidWithInvalidToken(t *testing.T) {
	signingKey := "HS512"
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(-2 * time.Hour).Unix() // set the expiration time to 2 hours
	token, err := Generate(signingKey, miniClaims, tokenKey)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	valid := IsValid(fmt.Sprintf("Bearer %s", token), tokenKey)
	if valid {
		t.Fatalf("expected false found %v", valid)
	}
}

func TestIsValidDefault(t *testing.T) {
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(2 * time.Hour).Unix() // set the expiration time to 2 hours
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	valid := IsValidDefault(fmt.Sprintf("Bearer %s", token))
	if !valid {
		t.Fatalf("expected true found %v", valid)
	}
}

func TestIsValidDefaultWithInvalidToken(t *testing.T) {
	miniClaims := randomMiniClaims()
	miniClaims.ExpiresAt = time.Now().Add(-2 * time.Hour).Unix() // set the expiration time to 2 hours
	token, err := GenerateWithDefault(miniClaims)

	if err != nil {
		t.Fatalf("error while creating token ->> %s", err)
	}
	if len(strings.TrimSpace(token)) < 60 {
		t.Fatal("invalid token generated")
	}

	// Refresh the generated token
	valid := IsValidDefault(fmt.Sprintf("Bearer %s", token))
	if valid {
		t.Fatalf("expected false found %v", valid)
	}
}

func randomMiniClaims() (claims *MiniClaims) {
	uid := uuid.New().String()
	username := fmt.Sprintf("%s@%s.com", uid[:5], uid[:5])
	claims = &MiniClaims{
		Data: map[string]interface{}{
			"uid":      uid,
			"username": username,
		},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: auth.DefaultExpirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "bellomnk",
			Subject:   "bellomnk client access credentials",
		},
	}
	return claims
}

func randomStandardClaims() (claims *jwt.StandardClaims) {
	standardClaims := &jwt.StandardClaims{
		Audience:  "client",
		Id:        uuid.New().String(),
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: auth.DefaultExpirationTime.Unix(),
		Issuer:    "bellomnk",
		Subject:   "bellomnk client access credentials",
	}
	return standardClaims
}

func randomMapClaims() (claims *jwt.MapClaims) {
	mapClaims := &jwt.MapClaims{
		"Audience":  "client",
		"Id":        uuid.New().String(),
		"IssuedAt":  time.Now().Unix(),
		"ExpiresAt": auth.DefaultExpirationTime.Unix(),
		"Issuer":    "bellomnk",
		"Subject":   "bellomnk client access credentials",
	}
	return mapClaims
}

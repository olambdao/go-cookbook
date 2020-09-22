package jwt

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type AccessToken struct {
	AccessKey string
	ExpiresAt int64
	Scope     string
}

type jwtClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

// Encode returns signed AccessToken
func Encode(token AccessToken, secret string) (string, error) {
	claims := jwtClaims{
		token.Scope,
		jwt.StandardClaims{
			Subject:   token.AccessKey,
			ExpiresAt: token.ExpiresAt,
		},
	}

	jt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return jt.SignedString([]byte(secret))
}

// Decode convert AccessToken string to object.
func Decode(tokenString string, secret string) (*AccessToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	// Convert jwtClaims to AccessToken
	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {
		return newToken(claims), nil
	} else {
		return nil, err
	}
}

// DecodeUnverified convert AccessToken string to object without verification.
func DecodeUnverified(tokenString string) (*AccessToken, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenString, &jwtClaims{})

	if err != nil {
		return nil, err
	}

	// Convert jwtClaims to AccessToken
	if claims, ok := token.Claims.(*jwtClaims); ok {
		return newToken(claims), nil
	} else {
		return nil, err
	}
}

func newToken(c *jwtClaims) *AccessToken {
	return &AccessToken{
		AccessKey: c.Subject,
		ExpiresAt: c.ExpiresAt,
		Scope:     c.Scope,
	}
}

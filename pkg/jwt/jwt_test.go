package jwt_test

import (
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/olambdao/go-cookbook/pkg/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewToken(t *testing.T) {
	token := jwt.AccessToken{
		AccessKey: "liam",
		ExpiresAt: 1580601600, // 02/02/2020 @ 12:00am (UTC)
		Scope:     "kct",
	}

	encoded, err := jwt.Encode(token, "secret")

	assert.NoError(t, err)
	assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImtjdCIsImV4cCI6MTU4MDYwMTYwMCwic3ViIjoibGlhbSJ9.sc9USQiMoxCPmfQ7ROaofBPkV2E90EE1HUwRkLB9cnE", encoded)
}

func TestDecodeToken(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImtjdCIsImNoYWluX2lkIjoiMTAwMSIsImV4cCI6MTU4MDYwMTYwMCwic3ViIjoibGlhbSJ9.5MkESRw1pj0xEaoNrmR0RK4zH7gXGkwDriU2ModmqYI"

	at(time.Unix(0, 0), func() {
		a, err := jwt.Decode(tokenString, "secret")

		assert.NoError(t, err)
		assert.Equal(t, "liam", a.AccessKey)
		assert.Equal(t, int64(1580601600), a.ExpiresAt)
		assert.Equal(t, "kct", a.Scope)
	})
}

func TestDecodeToken_expired(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImtjdCIsImNoYWluX2lkIjoiMTAwMSIsImV4cCI6MTU4MDYwMTYwMCwic3ViIjoibGlhbSJ9.5MkESRw1pj0xEaoNrmR0RK4zH7gXGkwDriU2ModmqYI"

	at(time.Unix(1580601600+1, 0), func() {
		_, err := jwt.Decode(tokenString, "secret")

		assert.Error(t, err)
		assert.EqualError(t, err, "token is expired by 1s")
	})
}

func TestDecodeToken_invalidToken0(t *testing.T) {
	tokenString := ""

	_, err := jwt.Decode(tokenString, "secret")

	assert.Error(t, err)
	assert.EqualError(t, err, "token contains an invalid number of segments")
}

func TestDecodeToken_invalidToken1(t *testing.T) {
	tokenString := "aa.bb.cc"

	_, err := jwt.Decode(tokenString, "secret")

	assert.Error(t, err)
	assert.EqualError(t, err, "invalid character 'i' looking for beginning of value")
}

func TestDecodeToken_noSignature(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImtjdCIsIm5ldHdvcmtfaWQiOiIxMDAxIiwiZXhwIjoxNTgwNjAxNjAwLCJzdWIiOiJsaWFtIn0"

	_, err := jwt.Decode(tokenString, "secret")

	assert.Error(t, err)
	assert.EqualError(t, err, "token contains an invalid number of segments")
}

func TestDecodeToken_invalidSecret(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImtjdCIsImNoYWluX2lkIjoiMTAwMSIsImV4cCI6MTU4MDYwMTYwMCwic3ViIjoibGlhbSJ9.5MkESRw1pj0xEaoNrmR0RK4zH7gXGkwDriU2ModmqYI"

	_, err := jwt.Decode(tokenString, "invalidSecret")

	assert.Error(t, err)
	assert.EqualError(t, err, "signature is invalid")
}

func TestDecodeToken_invalidHeader(t *testing.T) {
	tokenString := "e30.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"

	_, err := jwt.Decode(tokenString, "secret")

	assert.Error(t, err)
	assert.EqualError(t, err, "signing method (alg) is unspecified.")
}

func TestDecodeToken_unavailableAlgorithm(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1MSIsInR5cCI6IkpXVCJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ"

	_, err := jwt.Decode(tokenString, "secret")

	assert.Error(t, err)
	assert.EqualError(t, err, "signing method (alg) is unavailable.")
}

func TestDecodeUnverfiedToken(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6ImtjdCIsImNoYWluX2lkIjoiMTAwMSIsImV4cCI6MTU4MDYwMTYwMCwic3ViIjoibGlhbSJ9.5MkESRw1pj0xEaoNrmR0RK4zH7gXGkwDriU2ModmqYI"

	at(time.Unix(0, 0), func() {
		a, err := jwt.DecodeUnverified(tokenString)

		assert.NoError(t, err)
		assert.Equal(t, "liam", a.AccessKey)
		assert.Equal(t, int64(1580601600), a.ExpiresAt)
		assert.Equal(t, "kct", a.Scope)
	})
}

// Override time value for tests.  Restore default value after.
func at(t time.Time, f func()) {
	jwtgo.TimeFunc = func() time.Time {
		return t
	}
	f()
	jwtgo.TimeFunc = time.Now
}

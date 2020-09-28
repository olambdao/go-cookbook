package extract

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/alecthomas/assert"
)

// 리소스를 바디에서 추출
func TestExtractResourceFromBody(t *testing.T) {
	body := `{"krn": "krn:wallet:1234:1234"}`
	req, err := http.NewRequest("", "", bytes.NewBufferString(body))
	assert.NoError(t, err)

	r, err := extractResource(req, `${body:krn}`)
	assert.NoError(t, err)
	assert.Equal(t, "krn:wallet:1234:1234", r)
}

// 리소스를 헤더에서 추출
func TestExtractResourceFromHeader(t *testing.T) {
	req, err := http.NewRequest("", "", nil)
	req.Header.Add("test", "krn:wallet:1234:1234")
	assert.NoError(t, err)

	r, err := extractResource(req, `${header:test}`)
	assert.NoError(t, err)
	assert.Equal(t, "krn:wallet:1234:1234", r)
}

// 리소스를 쿼리 스트링에서 추출
func TestExtractResourceFromQuery(t *testing.T) {
	req, err := http.NewRequest("", "/api?krn=krn:wallet:1234:1234", nil)
	assert.NoError(t, err)

	r, err := extractResource(req, `${query:krn}`)
	assert.NoError(t, err)
	assert.Equal(t, "krn:wallet:1234:1234", r)
}

// 리소스를 x-krn 헤더에서 우선적으로 추출하는지 검증
func TestExtractResourceFromXKrnHeader(t *testing.T) {
	body := `{"krn": "krn:wallet:1234:1234"}`
	req, err := http.NewRequest("", "", bytes.NewBufferString(body))
	assert.NoError(t, err)
	req.Header.Add("x-krn", "header-value")

	r, err := extractResource(req, `${body:krn}`)
	assert.NoError(t, err)
	assert.Equal(t, "header-value", r)
}

func TestExtractResource(t *testing.T) {
	req, err := http.NewRequest("", "", nil)
	assert.NoError(t, err)

	r, err := extractResource(req, "*")
	assert.NoError(t, err)
	assert.Equal(t, "*", r)
}

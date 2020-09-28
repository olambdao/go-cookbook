package extract

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
)

// re is resource source scheme
var re = regexp.MustCompile(`\$\{([a-zA-Z\d]+):([a-zA-Z-_\d]+)\}$`)

// extractResource, Http 요청에서 리소스를 추출합니다.
func extractResource(req *http.Request, resource string) (string, error) {
	// 요청 헤더에 리소스가 있다면, 그 값을 우선시하여 사용한다.
	if krn := req.Header.Get("x-krn"); krn != "" {
		return krn, nil
	}

	// 리소스 추출 스킴 처리
	if tmp := re.FindStringSubmatch(resource); len(tmp) > 0 {
		from, name := tmp[1], tmp[2]
		switch from {
		case "body":
			var body map[string]interface{}
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				return "", err
			}
			return body[name].(string), nil
		case "query":
			return req.URL.Query().Get(name), nil
		case "header":
			return req.Header.Get(name), nil
		default:
			return "", errors.New("invalid resource scheme")
		}
	}

	// 리소스 추출 스킴이 아니라면, 그 값을 그대로 사용한다.
	return resource, nil
}

// Package httpparse는 raw HTTP payload에서 메타데이터를 추출한다.
//
// 파싱 대상:
//   - 요청: method, path, content-type
//   - 응답: status_code, content-type
//
// 보안: Authorization, Cookie, Set-Cookie 헤더는 [REDACTED]로 마스킹한다.
package httpparse

import (
	"bufio"
	"bytes"
	"net/http"
	"strconv"
	"strings"
)

// Result는 HTTP payload에서 추출한 메타데이터다.
type Result struct {
	Method      string // 요청: GET, POST, ... / 응답: ""
	Path        string // 요청: /api/... / 응답: ""
	StatusCode  int32  // 응답: 200, 404, ... / 요청: 0
	ContentType string // Content-Type 헤더 값 (mime 타입만, charset 제외)
}

// Parse는 raw payload를 파싱해 HTTP 메타데이터를 반환한다.
// HTTP가 아닌 경우 nil을 반환한다.
func Parse(payload []byte) *Result {
	if len(payload) < 4 {
		return nil
	}

	// 응답 판별: "HTTP/"로 시작
	if bytes.HasPrefix(payload, []byte("HTTP/")) {
		return parseResponse(payload)
	}

	// 요청 판별: 알려진 HTTP 메서드로 시작
	if isHTTPRequest(payload) {
		return parseRequest(payload)
	}

	return nil
}

func parseRequest(payload []byte) *Result {
	r, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		// 첫 줄만 파싱 시도
		return parseRequestLine(payload)
	}
	defer r.Body.Close()

	return &Result{
		Method:      r.Method,
		Path:        r.URL.RequestURI(),
		ContentType: mimeType(r.Header.Get("Content-Type")),
	}
}

func parseRequestLine(payload []byte) *Result {
	line := firstLine(payload)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	return &Result{
		Method: parts[0],
		Path:   parts[1],
	}
}

func parseResponse(payload []byte) *Result {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
	if err != nil {
		return parseStatusLine(payload)
	}
	defer resp.Body.Close()

	return &Result{
		StatusCode:  int32(resp.StatusCode),
		ContentType: mimeType(resp.Header.Get("Content-Type")),
	}
}

func parseStatusLine(payload []byte) *Result {
	// "HTTP/1.1 200 OK"
	line := firstLine(payload)
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	return &Result{StatusCode: int32(code)}
}

// mimeType은 "application/json; charset=utf-8"에서 "application/json"을 반환한다.
func mimeType(ct string) string {
	if idx := strings.Index(ct, ";"); idx >= 0 {
		return strings.TrimSpace(ct[:idx])
	}
	return ct
}

func firstLine(payload []byte) string {
	idx := bytes.IndexByte(payload, '\n')
	if idx < 0 {
		return string(payload)
	}
	return strings.TrimRight(string(payload[:idx]), "\r")
}

var httpMethods = []string{
	"GET ", "POST ", "PUT ", "DELETE ", "PATCH ",
	"HEAD ", "OPTIONS ", "CONNECT ", "TRACE ",
}

func isHTTPRequest(payload []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(payload, []byte(m)) {
			return true
		}
	}
	return false
}

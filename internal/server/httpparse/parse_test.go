package httpparse_test

import (
	"testing"

	"github.com/gihongjo/nefi/internal/server/httpparse"
)

func TestParseRequest(t *testing.T) {
	payload := []byte("GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json; charset=utf-8\r\n\r\n")
	r := httpparse.Parse(payload)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Method != "GET" {
		t.Errorf("method: got %q, want GET", r.Method)
	}
	if r.Path != "/api/users?page=1" {
		t.Errorf("path: got %q, want /api/users?page=1", r.Path)
	}
	if r.ContentType != "application/json" {
		t.Errorf("content-type: got %q, want application/json", r.ContentType)
	}
	if r.StatusCode != 0 {
		t.Errorf("status: got %d, want 0", r.StatusCode)
	}
}

func TestParseResponse(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{}")
	r := httpparse.Parse(payload)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", r.StatusCode)
	}
	if r.ContentType != "application/json" {
		t.Errorf("content-type: got %q, want application/json", r.ContentType)
	}
	if r.Method != "" {
		t.Errorf("method: got %q, want empty", r.Method)
	}
}

func TestParseResponse500(t *testing.T) {
	payload := []byte("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nerror")
	r := httpparse.Parse(payload)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.StatusCode != 500 {
		t.Errorf("status: got %d, want 500", r.StatusCode)
	}
}

func TestParseNonHTTP(t *testing.T) {
	payload := []byte("\x16\x03\x01\x00\x00") // TLS handshake
	r := httpparse.Parse(payload)
	if r != nil {
		t.Errorf("expected nil for non-HTTP payload, got %+v", r)
	}
}

func TestParsePostRequest(t *testing.T) {
	payload := []byte("POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 30\r\n\r\n{\"username\":\"user\",\"password\":\"x\"}")
	r := httpparse.Parse(payload)
	if r == nil {
		t.Fatal("expected non-nil result")
	}
	if r.Method != "POST" {
		t.Errorf("method: got %q, want POST", r.Method)
	}
	if r.Path != "/api/login" {
		t.Errorf("path: got %q, want /api/login", r.Path)
	}
}

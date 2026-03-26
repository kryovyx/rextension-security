package security_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	security "github.com/kryovyx/rextension-security"
)

// ---------------------------------------------------------------------------
// BearerScheme
// ---------------------------------------------------------------------------

func TestNewBearerScheme_DefaultName(t *testing.T) {
	s := security.NewBearerScheme("", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	if s.Name() != "bearer" {
		t.Fatalf("expected default name 'bearer', got %q", s.Name())
	}
}

func TestNewBearerScheme_CustomName(t *testing.T) {
	s := security.NewBearerScheme("jwt", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	if s.Name() != "jwt" {
		t.Fatalf("expected name 'jwt', got %q", s.Name())
	}
}

func TestBearerScheme_Type(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	if s.Type() != "http" {
		t.Fatalf("expected type 'http', got %q", s.Type())
	}
}

func TestBearerScheme_Description(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	if s.Description() != "Bearer token authentication" {
		t.Fatalf("unexpected description: %q", s.Description())
	}
}

func TestBearerScheme_SetDescription(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	ret := s.SetDescription("custom desc")
	if ret != s {
		t.Fatal("SetDescription should return the same pointer for chaining")
	}
	if s.Description() != "custom desc" {
		t.Fatalf("expected 'custom desc', got %q", s.Description())
	}
}

func TestBearerScheme_BearerFormat(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	if s.BearerFormat() != "JWT" {
		t.Fatalf("expected default bearer format 'JWT', got %q", s.BearerFormat())
	}
}

func TestBearerScheme_SetBearerFormat(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	ret := s.SetBearerFormat("opaque")
	if ret != s {
		t.Fatal("SetBearerFormat should return the same pointer for chaining")
	}
	if s.BearerFormat() != "opaque" {
		t.Fatalf("expected 'opaque', got %q", s.BearerFormat())
	}
}

func TestBearerScheme_Challenge(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return nil, nil }))
	if s.Challenge() != "Bearer" {
		t.Fatalf("expected 'Bearer', got %q", s.Challenge())
	}
}

func TestBearerScheme_Authenticate_MissingHeader(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return token, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
	if !strings.Contains(err.Error(), "missing Authorization header") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBearerScheme_Authenticate_WrongPrefix(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return token, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic abc")

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
	if !strings.Contains(err.Error(), "not Bearer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBearerScheme_Authenticate_EmptyToken(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) { return token, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer ")

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !strings.Contains(err.Error(), "empty bearer token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBearerScheme_Authenticate_ValidToken(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) {
		return "user:" + token, nil
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer mytoken123")

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "user:mytoken123" {
		t.Fatalf("expected 'user:mytoken123', got %v", principal)
	}
}

func TestBearerScheme_Authenticate_ValidateError(t *testing.T) {
	s := security.NewBearerScheme("b", security.BearerValidateFunc(func(token string) (interface{}, error) {
		return nil, fmt.Errorf("token expired")
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer expiredtoken")

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from validate function")
	}
	if !strings.Contains(err.Error(), "token expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// BasicScheme
// ---------------------------------------------------------------------------

func TestNewBasicScheme_DefaultName(t *testing.T) {
	s := security.NewBasicScheme("", "", func(u, p string) (interface{}, error) { return nil, nil })
	if s.Name() != "basic" {
		t.Fatalf("expected default name 'basic', got %q", s.Name())
	}
}

func TestNewBasicScheme_DefaultRealm(t *testing.T) {
	s := security.NewBasicScheme("basic", "", func(u, p string) (interface{}, error) { return nil, nil })
	// The default realm should appear in the Description.
	if !strings.Contains(s.Description(), "Restricted") {
		t.Fatalf("expected default realm 'Restricted' in description, got %q", s.Description())
	}
}

func TestNewBasicScheme_CustomNameAndRealm(t *testing.T) {
	s := security.NewBasicScheme("mybasic", "MyRealm", func(u, p string) (interface{}, error) { return nil, nil })
	if s.Name() != "mybasic" {
		t.Fatalf("expected name 'mybasic', got %q", s.Name())
	}
	if !strings.Contains(s.Description(), "MyRealm") {
		t.Fatalf("expected 'MyRealm' in description, got %q", s.Description())
	}
}

func TestBasicScheme_Type(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) { return nil, nil })
	if s.Type() != "http" {
		t.Fatalf("expected type 'http', got %q", s.Type())
	}
}

func TestBasicScheme_Challenge(t *testing.T) {
	s := security.NewBasicScheme("b", "TestRealm", func(u, p string) (interface{}, error) { return nil, nil })
	expected := `Basic realm="TestRealm"`
	if s.Challenge() != expected {
		t.Fatalf("expected %q, got %q", expected, s.Challenge())
	}
}

func TestBasicScheme_Challenge_DefaultRealm(t *testing.T) {
	s := security.NewBasicScheme("b", "", func(u, p string) (interface{}, error) { return nil, nil })
	expected := `Basic realm="Restricted"`
	if s.Challenge() != expected {
		t.Fatalf("expected %q, got %q", expected, s.Challenge())
	}
}

func TestBasicScheme_Authenticate_MissingHeader(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) { return u, nil })
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
	if !strings.Contains(err.Error(), "missing Authorization header") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBasicScheme_Authenticate_WrongPrefix(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) { return u, nil })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer xyz")

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for wrong prefix")
	}
	if !strings.Contains(err.Error(), "not Basic") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBasicScheme_Authenticate_InvalidBase64(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) { return u, nil })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Basic !!!invalid!!!")

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "invalid base64") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBasicScheme_Authenticate_MissingColon(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) { return u, nil })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Encode "nocolon" (no colon separator)
	encoded := base64.StdEncoding.EncodeToString([]byte("nocolon"))
	r.Header.Set("Authorization", "Basic "+encoded)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing colon")
	}
	if !strings.Contains(err.Error(), "invalid Basic auth format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBasicScheme_Authenticate_ValidCredentials(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) {
		return u + ":" + p, nil
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	r.Header.Set("Authorization", "Basic "+encoded)

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "alice:secret" {
		t.Fatalf("expected 'alice:secret', got %v", principal)
	}
}

func TestBasicScheme_Authenticate_ValidateError(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) {
		return nil, fmt.Errorf("invalid credentials")
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("bob:wrong"))
	r.Header.Set("Authorization", "Basic "+encoded)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from validate function")
	}
	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBasicScheme_Authenticate_EmptyPassword(t *testing.T) {
	s := security.NewBasicScheme("b", "r", func(u, p string) (interface{}, error) {
		return u, nil
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	encoded := base64.StdEncoding.EncodeToString([]byte("user:"))
	r.Header.Set("Authorization", "Basic "+encoded)

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "user" {
		t.Fatalf("expected 'user', got %v", principal)
	}
}

// ---------------------------------------------------------------------------
// APIKeyScheme
// ---------------------------------------------------------------------------

func TestNewAPIKeyScheme_DefaultName(t *testing.T) {
	s := security.NewAPIKeyScheme("", "X-API-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	if s.Name() != "apikey" {
		t.Fatalf("expected default name 'apikey', got %q", s.Name())
	}
}

func TestNewAPIKeyScheme_CustomName(t *testing.T) {
	s := security.NewAPIKeyScheme("mykey", "X-API-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	if s.Name() != "mykey" {
		t.Fatalf("expected name 'mykey', got %q", s.Name())
	}
}

func TestAPIKeyScheme_Type(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	if s.Type() != "apiKey" {
		t.Fatalf("expected type 'apiKey', got %q", s.Type())
	}
}

func TestAPIKeyScheme_Description(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	desc := s.Description()
	if !strings.Contains(desc, "header") || !strings.Contains(desc, "X-Key") {
		t.Fatalf("expected description to mention 'header' and 'X-Key', got %q", desc)
	}
}

func TestAPIKeyScheme_ParamName(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-My-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	if s.ParamName() != "X-My-Key" {
		t.Fatalf("expected 'X-My-Key', got %q", s.ParamName())
	}
}

func TestAPIKeyScheme_Location(t *testing.T) {
	sHeader := security.NewAPIKeyScheme("k", "X-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	if sHeader.Location() != security.APIKeyHeader {
		t.Fatalf("expected APIKeyHeader, got %q", sHeader.Location())
	}

	sQuery := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	if sQuery.Location() != security.APIKeyQuery {
		t.Fatalf("expected APIKeyQuery, got %q", sQuery.Location())
	}
}

func TestAPIKeyScheme_Challenge(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return nil, nil }))
	ch := s.Challenge()
	if !strings.Contains(ch, "X-API-Key") || !strings.Contains(ch, "header") {
		t.Fatalf("expected challenge to contain param name and location, got %q", ch)
	}
}

func TestAPIKeyScheme_Authenticate_Header_MissingKey(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return key, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing API key header")
	}
	if !strings.Contains(err.Error(), "missing API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeyScheme_Authenticate_Header_ValidKey(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) {
		return "key:" + key, nil
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", "abc123")

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "key:abc123" {
		t.Fatalf("expected 'key:abc123', got %v", principal)
	}
}

func TestAPIKeyScheme_Authenticate_Header_ValidateError(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, security.APIKeyValidateFunc(func(key string) (interface{}, error) {
		return nil, fmt.Errorf("invalid API key")
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-API-Key", "badkey")

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from validate function")
	}
	if !strings.Contains(err.Error(), "invalid API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeyScheme_Authenticate_Query_MissingKey(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return key, nil }))
	r := httptest.NewRequest(http.MethodGet, "/path", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing API key query param")
	}
	if !strings.Contains(err.Error(), "missing API key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeyScheme_Authenticate_Query_ValidKey(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, security.APIKeyValidateFunc(func(key string) (interface{}, error) {
		return "qkey:" + key, nil
	}))
	r := httptest.NewRequest(http.MethodGet, "/path?api_key=xyz789", nil)

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "qkey:xyz789" {
		t.Fatalf("expected 'qkey:xyz789', got %v", principal)
	}
}

func TestAPIKeyScheme_Authenticate_Query_ValidateError(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, security.APIKeyValidateFunc(func(key string) (interface{}, error) {
		return nil, fmt.Errorf("key revoked")
	}))
	r := httptest.NewRequest(http.MethodGet, "/path?api_key=revoked", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from validate function")
	}
	if !strings.Contains(err.Error(), "key revoked") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeyScheme_Authenticate_UnknownLocation(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "key", security.APIKeyLocation("grpc"), security.APIKeyValidateFunc(func(key string) (interface{}, error) { return key, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for unknown location")
	}
	if !strings.Contains(err.Error(), "unknown API key location") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeyScheme_Authenticate_Cookie_MissingCookie(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "session_id", security.APIKeyCookie, security.APIKeyValidateFunc(func(key string) (interface{}, error) { return key, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing cookie")
	}
	if !strings.Contains(err.Error(), "missing cookie") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIKeyScheme_Authenticate_Cookie_ValidKey(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "session_id", security.APIKeyCookie, security.APIKeyValidateFunc(func(key string) (interface{}, error) {
		return "session:" + key, nil
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: "abc123"})

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "session:abc123" {
		t.Fatalf("expected 'session:abc123', got %v", principal)
	}
}

func TestAPIKeyScheme_Authenticate_Cookie_ValidateError(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "session_id", security.APIKeyCookie, security.APIKeyValidateFunc(func(key string) (interface{}, error) {
		return nil, fmt.Errorf("session expired")
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "session_id", Value: "old-session"})

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from validate function")
	}
	if !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SessionCookieScheme
// ---------------------------------------------------------------------------

func TestNewSessionCookieScheme_DefaultName(t *testing.T) {
	s := security.NewSessionCookieScheme("", "", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.Name() != "sessionCookie" {
		t.Fatalf("expected default name 'sessionCookie', got %q", s.Name())
	}
}

func TestNewSessionCookieScheme_DefaultCookieName(t *testing.T) {
	s := security.NewSessionCookieScheme("", "", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.CookieName() != "session_id" {
		t.Fatalf("expected default cookie name 'session_id', got %q", s.CookieName())
	}
}

func TestNewSessionCookieScheme_CustomFields(t *testing.T) {
	s := security.NewSessionCookieScheme("bff", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.Name() != "bff" {
		t.Fatalf("expected name 'bff', got %q", s.Name())
	}
	if s.CookieName() != "sid" {
		t.Fatalf("expected cookie name 'sid', got %q", s.CookieName())
	}
}

func TestSessionCookieScheme_Type(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.Type() != "apiKey" {
		t.Fatalf("expected type 'apiKey', got %q", s.Type())
	}
}

func TestSessionCookieScheme_Location(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.Location() != "cookie" {
		t.Fatalf("expected location 'cookie', got %q", s.Location())
	}
}

func TestSessionCookieScheme_ParamName(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "my_session", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.ParamName() != "my_session" {
		t.Fatalf("expected param name 'my_session', got %q", s.ParamName())
	}
}

func TestSessionCookieScheme_Challenge_Empty(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	if s.Challenge() != "" {
		t.Fatalf("expected empty challenge, got %q", s.Challenge())
	}
}

func TestSessionCookieScheme_SetDescription(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return nil, nil }))
	ret := s.SetDescription("BFF session")
	if ret != s {
		t.Fatal("SetDescription should return the same pointer for chaining")
	}
	if s.Description() != "BFF session" {
		t.Fatalf("expected 'BFF session', got %q", s.Description())
	}
}

func TestSessionCookieScheme_Authenticate_MissingCookie(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return id, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for missing session cookie")
	}
	if !strings.Contains(err.Error(), "missing session cookie") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCookieScheme_Authenticate_EmptyCookieValue(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) { return id, nil }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: ""})

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for empty session cookie value")
	}
	if !strings.Contains(err.Error(), "empty session cookie") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCookieScheme_Authenticate_ValidSession(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) {
		return map[string]string{"user": id}, nil
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "session-xyz"})

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := principal.(map[string]string)
	if !ok {
		t.Fatalf("expected map principal, got %T", principal)
	}
	if m["user"] != "session-xyz" {
		t.Fatalf("expected user 'session-xyz', got %q", m["user"])
	}
}

func TestSessionCookieScheme_Authenticate_ValidateError(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", security.SessionValidateFunc(func(id string) (interface{}, error) {
		return nil, fmt.Errorf("session not found")
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "expired-session"})

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from validate function")
	}
	if !strings.Contains(err.Error(), "session not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SessionCookieScheme — store-backed lifecycle (WithStore, IssueSession, RevokeSession)
// ---------------------------------------------------------------------------

// mockSessionStore is an in-memory SessionStore for testing.
type mockSessionStore struct {
	data   map[string]interface{}
	getErr error
	setErr error
	delErr error
}

func newMockStore() *mockSessionStore {
	return &mockSessionStore{data: make(map[string]interface{})}
}

func (m *mockSessionStore) Get(_ context.Context, id string) (interface{}, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	v, ok := m.data[id]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return v, nil
}

func (m *mockSessionStore) Set(_ context.Context, id string, p interface{}) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.data[id] = p
	return nil
}

func (m *mockSessionStore) Delete(_ context.Context, id string) error {
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.data, id)
	return nil
}

func TestSessionCookieScheme_WithStore_Authenticate_UsesStore(t *testing.T) {
	store := newMockStore()
	store.data["known-session"] = map[string]string{"user": "alice"}

	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "known-session"})

	principal, err := s.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, _ := principal.(map[string]string)
	if m["user"] != "alice" {
		t.Fatalf("expected user 'alice', got %v", m["user"])
	}
}

func TestSessionCookieScheme_WithStore_Authenticate_StoreError(t *testing.T) {
	store := newMockStore()
	store.getErr = fmt.Errorf("session expired")

	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "old-session"})

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error from store")
	}
	if !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCookieScheme_Authenticate_NoStoreNoValidate(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "some-id"})

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error when no store or validate func configured")
	}
	if !strings.Contains(err.Error(), "no store or validate func") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCookieScheme_IssueSession_WritesSetCookieAndStoresSession(t *testing.T) {
	store := newMockStore()
	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)

	w := httptest.NewRecorder()
	principal := map[string]string{"user": "bob"}

	sessionID, err := s.IssueSession(context.Background(), w, principal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sessionID == "" {
		t.Fatal("expected non-empty session ID")
	}
	// Cookie must be present in the response.
	resp := w.Result()
	cookies := resp.Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == "sid" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("expected Set-Cookie header for 'sid'")
	}
	if found.Value != sessionID {
		t.Fatalf("cookie value %q != session ID %q", found.Value, sessionID)
	}
	// Principal must be stored in the store.
	stored, err := store.Get(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("expected principal in store: %v", err)
	}
	m, _ := stored.(map[string]string)
	if m["user"] != "bob" {
		t.Fatalf("stored user should be 'bob', got %v", m)
	}
}

func TestSessionCookieScheme_IssueSession_NoStore_Error(t *testing.T) {
	s := security.NewSessionCookieScheme("s", "sid", nil)
	w := httptest.NewRecorder()

	_, err := s.IssueSession(context.Background(), w, map[string]string{})
	if err == nil {
		t.Fatal("expected error when no store attached")
	}
	if !strings.Contains(err.Error(), "no SessionStore attached") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCookieScheme_IssueSession_StoreSetError(t *testing.T) {
	store := newMockStore()
	store.setErr = fmt.Errorf("db unavailable")
	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)

	w := httptest.NewRecorder()
	_, err := s.IssueSession(context.Background(), w, "principal")
	if err == nil {
		t.Fatal("expected error propagated from store.Set")
	}
	if !strings.Contains(err.Error(), "db unavailable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionCookieScheme_IssueSession_SessionID_IsUnique(t *testing.T) {
	store := newMockStore()
	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)
	w1, w2 := httptest.NewRecorder(), httptest.NewRecorder()

	id1, _ := s.IssueSession(context.Background(), w1, "p1")
	id2, _ := s.IssueSession(context.Background(), w2, "p2")
	if id1 == id2 {
		t.Fatal("expected unique session IDs")
	}
}

func TestSessionCookieScheme_IssueSession_WithCookieOptions(t *testing.T) {
	store := newMockStore()
	s := security.NewSessionCookieScheme("s", "sid", nil).
		WithStore(store).
		WithCookieOptions(security.CookieOptions{
			MaxAge:   3600,
			Path:     "/api",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

	w := httptest.NewRecorder()
	_, err := s.IssueSession(context.Background(), w, "principal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "sid" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("expected Set-Cookie for 'sid'")
	}
	if found.MaxAge != 3600 {
		t.Errorf("expected MaxAge 3600, got %d", found.MaxAge)
	}
	if found.Path != "/api" {
		t.Errorf("expected Path '/api', got %q", found.Path)
	}
	if !found.Secure {
		t.Error("expected Secure to be true")
	}
	if !found.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
}

func TestSessionCookieScheme_RevokeSession_ClearsSessionAndCookie(t *testing.T) {
	store := newMockStore()
	store.data["live-session"] = map[string]string{"user": "carol"}
	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "live-session"})

	if err := s.RevokeSession(context.Background(), w, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Session must be gone from the store.
	_, err := store.Get(context.Background(), "live-session")
	if err == nil {
		t.Fatal("expected session to be deleted from store")
	}
	// Response must contain a clearing Set-Cookie.
	var found *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "sid" {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatal("expected clearing Set-Cookie header")
	}
	if found.MaxAge != -1 {
		t.Errorf("expected MaxAge -1 for cookie clear, got %d", found.MaxAge)
	}
}

func TestSessionCookieScheme_RevokeSession_NoCookieIsNoOp(t *testing.T) {
	store := newMockStore()
	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/", nil) // no cookie

	if err := s.RevokeSession(context.Background(), w, r); err != nil {
		t.Fatalf("unexpected error on no-op revoke: %v", err)
	}
}

func TestSessionCookieScheme_RevokeSession_StoreDeleteError(t *testing.T) {
	store := newMockStore()
	store.data["some-session"] = "principal"
	store.delErr = fmt.Errorf("db write failed")
	s := security.NewSessionCookieScheme("s", "sid", nil).WithStore(store)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "some-session"})

	err := s.RevokeSession(context.Background(), w, r)
	if err == nil {
		t.Fatal("expected error from store.Delete")
	}
	if !strings.Contains(err.Error(), "db write failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

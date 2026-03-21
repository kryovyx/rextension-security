package security_test

import (
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
	s := security.NewBearerScheme("", func(token string) (interface{}, error) { return nil, nil })
	if s.Name() != "bearer" {
		t.Fatalf("expected default name 'bearer', got %q", s.Name())
	}
}

func TestNewBearerScheme_CustomName(t *testing.T) {
	s := security.NewBearerScheme("jwt", func(token string) (interface{}, error) { return nil, nil })
	if s.Name() != "jwt" {
		t.Fatalf("expected name 'jwt', got %q", s.Name())
	}
}

func TestBearerScheme_Type(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return nil, nil })
	if s.Type() != "http" {
		t.Fatalf("expected type 'http', got %q", s.Type())
	}
}

func TestBearerScheme_Description(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return nil, nil })
	if s.Description() != "Bearer token authentication" {
		t.Fatalf("unexpected description: %q", s.Description())
	}
}

func TestBearerScheme_SetDescription(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return nil, nil })
	ret := s.SetDescription("custom desc")
	if ret != s {
		t.Fatal("SetDescription should return the same pointer for chaining")
	}
	if s.Description() != "custom desc" {
		t.Fatalf("expected 'custom desc', got %q", s.Description())
	}
}

func TestBearerScheme_BearerFormat(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return nil, nil })
	if s.BearerFormat() != "JWT" {
		t.Fatalf("expected default bearer format 'JWT', got %q", s.BearerFormat())
	}
}

func TestBearerScheme_SetBearerFormat(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return nil, nil })
	ret := s.SetBearerFormat("opaque")
	if ret != s {
		t.Fatal("SetBearerFormat should return the same pointer for chaining")
	}
	if s.BearerFormat() != "opaque" {
		t.Fatalf("expected 'opaque', got %q", s.BearerFormat())
	}
}

func TestBearerScheme_Challenge(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return nil, nil })
	if s.Challenge() != "Bearer" {
		t.Fatalf("expected 'Bearer', got %q", s.Challenge())
	}
}

func TestBearerScheme_Authenticate_MissingHeader(t *testing.T) {
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return token, nil })
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
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return token, nil })
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
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) { return token, nil })
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
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) {
		return "user:" + token, nil
	})
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
	s := security.NewBearerScheme("b", func(token string) (interface{}, error) {
		return nil, fmt.Errorf("token expired")
	})
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
	s := security.NewAPIKeyScheme("", "X-API-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	if s.Name() != "apikey" {
		t.Fatalf("expected default name 'apikey', got %q", s.Name())
	}
}

func TestNewAPIKeyScheme_CustomName(t *testing.T) {
	s := security.NewAPIKeyScheme("mykey", "X-API-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	if s.Name() != "mykey" {
		t.Fatalf("expected name 'mykey', got %q", s.Name())
	}
}

func TestAPIKeyScheme_Type(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	if s.Type() != "apiKey" {
		t.Fatalf("expected type 'apiKey', got %q", s.Type())
	}
}

func TestAPIKeyScheme_Description(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	desc := s.Description()
	if !strings.Contains(desc, "header") || !strings.Contains(desc, "X-Key") {
		t.Fatalf("expected description to mention 'header' and 'X-Key', got %q", desc)
	}
}

func TestAPIKeyScheme_ParamName(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-My-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	if s.ParamName() != "X-My-Key" {
		t.Fatalf("expected 'X-My-Key', got %q", s.ParamName())
	}
}

func TestAPIKeyScheme_Location(t *testing.T) {
	sHeader := security.NewAPIKeyScheme("k", "X-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	if sHeader.Location() != security.APIKeyHeader {
		t.Fatalf("expected APIKeyHeader, got %q", sHeader.Location())
	}

	sQuery := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, func(key string) (interface{}, error) { return nil, nil })
	if sQuery.Location() != security.APIKeyQuery {
		t.Fatalf("expected APIKeyQuery, got %q", sQuery.Location())
	}
}

func TestAPIKeyScheme_Challenge(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return nil, nil })
	ch := s.Challenge()
	if !strings.Contains(ch, "X-API-Key") || !strings.Contains(ch, "header") {
		t.Fatalf("expected challenge to contain param name and location, got %q", ch)
	}
}

func TestAPIKeyScheme_Authenticate_Header_MissingKey(t *testing.T) {
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, func(key string) (interface{}, error) { return key, nil })
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
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, func(key string) (interface{}, error) {
		return "key:" + key, nil
	})
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
	s := security.NewAPIKeyScheme("k", "X-API-Key", security.APIKeyHeader, func(key string) (interface{}, error) {
		return nil, fmt.Errorf("invalid API key")
	})
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
	s := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, func(key string) (interface{}, error) { return key, nil })
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
	s := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, func(key string) (interface{}, error) {
		return "qkey:" + key, nil
	})
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
	s := security.NewAPIKeyScheme("k", "api_key", security.APIKeyQuery, func(key string) (interface{}, error) {
		return nil, fmt.Errorf("key revoked")
	})
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
	s := security.NewAPIKeyScheme("k", "key", security.APIKeyLocation("cookie"), func(key string) (interface{}, error) { return key, nil })
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := s.Authenticate(r)
	if err == nil {
		t.Fatal("expected error for unknown location")
	}
	if !strings.Contains(err.Error(), "unknown API key location") {
		t.Fatalf("unexpected error: %v", err)
	}
}

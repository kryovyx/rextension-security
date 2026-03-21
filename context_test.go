package security_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	security "github.com/kryovyx/rextension-security"
)

func TestGetPrincipal_Found(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), security.ContextKeyPrincipal, "alice")
	r = r.WithContext(ctx)

	principal, ok := security.GetPrincipal(r)
	if !ok {
		t.Fatal("expected ok=true when principal is set")
	}
	if principal != "alice" {
		t.Fatalf("expected 'alice', got %v", principal)
	}
}

func TestGetPrincipal_NotFound(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	principal, ok := security.GetPrincipal(r)
	if ok {
		t.Fatal("expected ok=false when principal is not set")
	}
	if principal != nil {
		t.Fatalf("expected nil principal, got %v", principal)
	}
}

func TestGetPrincipalAs_CorrectType(t *testing.T) {
	type User struct {
		Name string
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), security.ContextKeyPrincipal, User{Name: "bob"})
	r = r.WithContext(ctx)

	user, ok := security.GetPrincipalAs[User](r)
	if !ok {
		t.Fatal("expected ok=true for correct type assertion")
	}
	if user.Name != "bob" {
		t.Fatalf("expected 'bob', got %q", user.Name)
	}
}

func TestGetPrincipalAs_WrongType(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), security.ContextKeyPrincipal, "stringprincipal")
	r = r.WithContext(ctx)

	val, ok := security.GetPrincipalAs[int](r)
	if ok {
		t.Fatal("expected ok=false for wrong type assertion")
	}
	if val != 0 {
		t.Fatalf("expected zero value, got %v", val)
	}
}

func TestGetPrincipalAs_Nil(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	val, ok := security.GetPrincipalAs[string](r)
	if ok {
		t.Fatal("expected ok=false when no principal is set")
	}
	if val != "" {
		t.Fatalf("expected zero value, got %q", val)
	}
}

func TestGetPrincipalAs_PointerType(t *testing.T) {
	type Token struct{ Sub string }
	tok := &Token{Sub: "sub123"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), security.ContextKeyPrincipal, tok)
	r = r.WithContext(ctx)

	got, ok := security.GetPrincipalAs[*Token](r)
	if !ok {
		t.Fatal("expected ok=true for pointer type")
	}
	if got.Sub != "sub123" {
		t.Fatalf("expected 'sub123', got %q", got.Sub)
	}
}

func TestGetSchemeName_Found(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), security.ContextKeySchemeName, "bearer")
	r = r.WithContext(ctx)

	name := security.GetSchemeName(r)
	if name != "bearer" {
		t.Fatalf("expected 'bearer', got %q", name)
	}
}

func TestGetSchemeName_NotFound(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	name := security.GetSchemeName(r)
	if name != "" {
		t.Fatalf("expected empty string, got %q", name)
	}
}

func TestGetSchemeName_WrongType(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), security.ContextKeySchemeName, 12345)
	r = r.WithContext(ctx)

	name := security.GetSchemeName(r)
	if name != "" {
		t.Fatalf("expected empty string for non-string value, got %q", name)
	}
}

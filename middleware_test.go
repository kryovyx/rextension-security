package security_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	rxroute "github.com/kryovyx/rextension/route"

	security "github.com/kryovyx/rextension-security"
)

// ---------------------------------------------------------------------------
// Mock types
// ---------------------------------------------------------------------------

// mockSecuredRoute implements both rxroute.Route and security.SecuredRoute.
type mockSecuredRoute struct {
	method  string
	path    string
	schemes []string
}

func (m *mockSecuredRoute) Method() string               { return m.method }
func (m *mockSecuredRoute) Path() string                 { return m.path }
func (m *mockSecuredRoute) Handler() rxroute.HandlerFunc { return nil }
func (m *mockSecuredRoute) RequiredSchemes() []string    { return m.schemes }

// mockPlainRoute implements rxroute.Route but NOT SecuredRoute.
type mockPlainRoute struct {
	method string
	path   string
}

func (m *mockPlainRoute) Method() string               { return m.method }
func (m *mockPlainRoute) Path() string                 { return m.path }
func (m *mockPlainRoute) Handler() rxroute.HandlerFunc { return nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func buildMiddleware(schemes []security.SecurityScheme) func(http.Handler) http.Handler {
	cfg := security.NewTestMiddlewareConfig(schemes)
	return security.SecurityMiddleware(cfg)
}

// withRoute stores rt as the matched route on req, mirroring what the rex
// router does in ServeHTTP before handing off to the middleware chain.
func withRoute(req *http.Request, rt rxroute.Route) *http.Request {
	return req.WithContext(rxroute.SetMatchedRoute(req.Context(), rt))
}

func nextOK(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// ---------------------------------------------------------------------------
// Tests: No matched route in context -> passthrough
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_NoMatchedRoute(t *testing.T) {
	mw := buildMiddleware(nil)

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/not-registered", nil)
	// No matched route set in context.
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected next handler to be called when no matched route in context")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Tests: Matched route does not implement SecuredRoute -> passthrough
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_PlainRoute(t *testing.T) {
	plainRoute := &mockPlainRoute{method: "GET", path: "/public"}
	mw := buildMiddleware(nil)

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/public", nil), plainRoute)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected next handler to be called for plain (non-secured) route")
	}
}

// ---------------------------------------------------------------------------
// Tests: SecuredRoute with empty RequiredSchemes -> public passthrough
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_EmptyRequiredSchemes(t *testing.T) {
	secRoute := &mockSecuredRoute{method: "GET", path: "/open", schemes: []string{}}
	mw := buildMiddleware(nil)

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/open", nil), secRoute)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected next handler to be called for public secured route (empty schemes)")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Tests: Auth succeeds -> principal stored, next called
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_AuthSuccess(t *testing.T) {
	scheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return "user:" + token, nil
	}))
	secRoute := &mockSecuredRoute{method: "GET", path: "/protected", schemes: []string{"bearer"}}
	mw := buildMiddleware([]security.SecurityScheme{scheme})

	var capturedPrincipal interface{}
	var capturedScheme string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = security.GetPrincipal(r)
		capturedScheme = security.GetSchemeName(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(inner)
	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/protected", nil), secRoute)
	req.Header.Set("Authorization", "Bearer validtoken")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedPrincipal != "user:validtoken" {
		t.Fatalf("expected principal 'user:validtoken', got %v", capturedPrincipal)
	}
	if capturedScheme != "bearer" {
		t.Fatalf("expected scheme name 'bearer', got %q", capturedScheme)
	}
}

// ---------------------------------------------------------------------------
// Tests: Auth fails -> 401 with WWW-Authenticate
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_AuthFailure(t *testing.T) {
	scheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return nil, fmt.Errorf("invalid token")
	}))
	secRoute := &mockSecuredRoute{method: "POST", path: "/secret", schemes: []string{"bearer"}}
	mw := buildMiddleware([]security.SecurityScheme{scheme})

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodPost, "/secret", nil), secRoute)
	req.Header.Set("Authorization", "Bearer badtoken")
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler should NOT be called on auth failure")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "Bearer") {
		t.Fatalf("expected WWW-Authenticate to contain 'Bearer', got %q", wwwAuth)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "401 Unauthorized") {
		t.Fatalf("expected 401 Unauthorized in body, got %q", body)
	}
}

func TestSecurityMiddleware_AuthFailure_MissingHeader(t *testing.T) {
	scheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return "ok", nil
	}))
	secRoute := &mockSecuredRoute{method: "GET", path: "/guarded", schemes: []string{"bearer"}}
	mw := buildMiddleware([]security.SecurityScheme{scheme})

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/guarded", nil), secRoute)
	// No Authorization header.
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler should NOT be called when auth header is missing")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Tests: Unknown scheme -> 500
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_UnknownScheme(t *testing.T) {
	secRoute := &mockSecuredRoute{method: "GET", path: "/mystery", schemes: []string{"nonexistent"}}
	mw := buildMiddleware(nil) // no schemes registered

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/mystery", nil), secRoute)
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler should NOT be called for unknown scheme")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "unknown security scheme") {
		t.Fatalf("expected 'unknown security scheme' in body, got %q", body)
	}
}

// ---------------------------------------------------------------------------
// Tests: Multiple schemes - all succeed
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_MultipleSchemes_AllSucceed(t *testing.T) {
	bearerScheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return "bearer-user", nil
	}))
	apiKeyScheme := security.NewAPIKeyScheme("apikey", "X-API-Key", security.APIKeyHeader, keyValidatorFunc(func(key string) (interface{}, error) {
		return "apikey-user", nil
	}))

	secRoute := &mockSecuredRoute{
		method:  "GET",
		path:    "/multi",
		schemes: []string{"bearer", "apikey"},
	}
	mw := buildMiddleware([]security.SecurityScheme{bearerScheme, apiKeyScheme})

	var capturedPrincipal interface{}
	var capturedScheme string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = security.GetPrincipal(r)
		capturedScheme = security.GetSchemeName(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := mw(inner)
	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/multi", nil), secRoute)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-API-Key", "key123")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// The last scheme to succeed sets the principal/scheme name.
	if capturedPrincipal != "apikey-user" {
		t.Fatalf("expected 'apikey-user' (last scheme principal), got %v", capturedPrincipal)
	}
	if capturedScheme != "apikey" {
		t.Fatalf("expected 'apikey', got %q", capturedScheme)
	}
}

// ---------------------------------------------------------------------------
// Tests: Multiple schemes - second fails
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_MultipleSchemes_SecondFails(t *testing.T) {
	bearerScheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return "bearer-user", nil
	}))
	apiKeyScheme := security.NewAPIKeyScheme("apikey", "X-API-Key", security.APIKeyHeader, keyValidatorFunc(func(key string) (interface{}, error) {
		return nil, fmt.Errorf("bad key")
	}))

	secRoute := &mockSecuredRoute{
		method:  "GET",
		path:    "/multi-fail",
		schemes: []string{"bearer", "apikey"},
	}
	mw := buildMiddleware([]security.SecurityScheme{bearerScheme, apiKeyScheme})

	called := false
	handler := mw(nextOK(&called))

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/multi-fail", nil), secRoute)
	req.Header.Set("Authorization", "Bearer goodtoken")
	req.Header.Set("X-API-Key", "badkey")
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler should NOT be called if any required scheme fails")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Tests: Route with path parameters is enforced correctly
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_PathParamRoute(t *testing.T) {
	scheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return "authed", nil
	}))
	// Route template has a path parameter — the router resolves the actual ID.
	secRoute := &mockSecuredRoute{method: "POST", path: "/connections/{connectionId}/licenses", schemes: []string{"bearer"}}
	mw := buildMiddleware([]security.SecurityScheme{scheme})

	var capturedPrincipal interface{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = security.GetPrincipal(r)
		w.WriteHeader(http.StatusOK)
	})

	// The router stores the matched route in context before middleware runs,
	// so the actual URL with a concrete ID is irrelevant here.
	handler := mw(inner)
	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodPost, "/internal/connections/abc-123/licenses", nil), secRoute)
	req.Header.Set("Authorization", "Bearer tok")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedPrincipal != "authed" {
		t.Fatalf("expected 'authed' principal, got %v", capturedPrincipal)
	}
}

// ---------------------------------------------------------------------------
// Tests: Different HTTP methods on same path
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_DifferentMethods(t *testing.T) {
	scheme := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return "authed", nil
	}))
	getRoute := &mockSecuredRoute{method: "GET", path: "/resource", schemes: []string{"bearer"}}
	mw := buildMiddleware([]security.SecurityScheme{scheme})

	// GET /resource with the secured route in context -> 401 (no auth header)
	rec := httptest.NewRecorder()
	called := false
	req := withRoute(httptest.NewRequest(http.MethodGet, "/resource", nil), getRoute)
	mw(nextOK(&called)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET expected 401, got %d", rec.Code)
	}

	// POST /resource -> no matched route in context -> passthrough
	rec = httptest.NewRecorder()
	called = false
	req = httptest.NewRequest(http.MethodPost, "/resource", nil)
	// No withRoute call — router would not have matched a POST route.
	mw(nextOK(&called)).ServeHTTP(rec, req)
	if !called {
		t.Fatal("POST should pass through when no matched route in context")
	}
}

// ---------------------------------------------------------------------------
// Tests: BasicScheme through middleware
// ---------------------------------------------------------------------------

func TestSecurityMiddleware_BasicScheme(t *testing.T) {
	scheme := security.NewBasicScheme("basic", "Test", func(u, p string) (interface{}, error) {
		if u == "admin" && p == "pass" {
			return "admin", nil
		}
		return nil, fmt.Errorf("bad creds")
	})
	secRoute := &mockSecuredRoute{method: "GET", path: "/basic", schemes: []string{"basic"}}
	mw := buildMiddleware([]security.SecurityScheme{scheme})

	var capturedPrincipal interface{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = security.GetPrincipal(r)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := withRoute(httptest.NewRequest(http.MethodGet, "/basic", nil), secRoute)
	req.SetBasicAuth("admin", "pass")
	mw(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capturedPrincipal != "admin" {
		t.Fatalf("expected principal 'admin', got %v", capturedPrincipal)
	}
}

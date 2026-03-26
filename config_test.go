package security_test

import (
	"net/http"
	"testing"

	security "github.com/kryovyx/rextension-security"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := security.NewDefaultConfig()
	if cfg == nil {
		t.Fatal("NewDefaultConfig returned nil")
	}
	if len(cfg.Schemes) != 0 {
		t.Fatalf("expected empty Schemes, got %d", len(cfg.Schemes))
	}
}

func TestWithScheme(t *testing.T) {
	scheme := security.NewBearerScheme("test", tokenValidatorFunc(func(token string) (interface{}, error) {
		return nil, nil
	}))

	opt := security.WithScheme(scheme)
	cfg := security.NewDefaultConfig()
	opt(cfg)

	if len(cfg.Schemes) != 1 {
		t.Fatalf("expected 1 scheme, got %d", len(cfg.Schemes))
	}
	if cfg.Schemes[0].Name() != "test" {
		t.Fatalf("expected scheme name 'test', got %q", cfg.Schemes[0].Name())
	}
}

func TestWithScheme_Multiple(t *testing.T) {
	s1 := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return nil, nil
	}))
	s2 := security.NewBasicScheme("basic", "realm", func(u, p string) (interface{}, error) {
		return nil, nil
	})

	cfg := security.NewDefaultConfig()
	security.WithScheme(s1)(cfg)
	security.WithScheme(s2)(cfg)

	if len(cfg.Schemes) != 2 {
		t.Fatalf("expected 2 schemes, got %d", len(cfg.Schemes))
	}
}

func TestNewConfig_NoOptions(t *testing.T) {
	cfg := security.NewConfig()
	if cfg == nil {
		t.Fatal("NewConfig returned nil")
	}
	if len(cfg.Schemes) != 0 {
		t.Fatalf("expected empty Schemes, got %d", len(cfg.Schemes))
	}
}

func TestNewConfig_WithOptions(t *testing.T) {
	scheme := security.NewBearerScheme("jwt", tokenValidatorFunc(func(token string) (interface{}, error) {
		return nil, nil
	}))

	cfg := security.NewConfig(security.WithScheme(scheme))
	if len(cfg.Schemes) != 1 {
		t.Fatalf("expected 1 scheme, got %d", len(cfg.Schemes))
	}
	if cfg.Schemes[0].Name() != "jwt" {
		t.Fatalf("expected scheme name 'jwt', got %q", cfg.Schemes[0].Name())
	}
}

func TestNewConfig_MultipleOptions(t *testing.T) {
	s1 := security.NewBearerScheme("bearer", tokenValidatorFunc(func(token string) (interface{}, error) {
		return nil, nil
	}))
	s2 := security.NewAPIKeyScheme("apikey", "X-API-Key", security.APIKeyHeader, keyValidatorFunc(func(key string) (interface{}, error) {
		return nil, nil
	}))

	cfg := security.NewConfig(security.WithScheme(s1), security.WithScheme(s2))
	if len(cfg.Schemes) != 2 {
		t.Fatalf("expected 2 schemes, got %d", len(cfg.Schemes))
	}
}

// Verify Config.Schemes can hold SecurityScheme interface implementations.
func TestConfig_SchemesField(t *testing.T) {
	cfg := &security.Config{
		Schemes: []security.SecurityScheme{
			security.NewBearerScheme("b", tokenValidatorFunc(func(token string) (interface{}, error) { return nil, nil })),
			security.NewBasicScheme("a", "", func(u, p string) (interface{}, error) { return nil, nil }),
			security.NewAPIKeyScheme("k", "key", security.APIKeyQuery, keyValidatorFunc(func(k string) (interface{}, error) { return nil, nil })),
		},
	}
	if len(cfg.Schemes) != 3 {
		t.Fatalf("expected 3 schemes, got %d", len(cfg.Schemes))
	}
}

// dummyScheme is a minimal SecurityScheme implementation for testing.
type dummyScheme struct{ n string }

func (d *dummyScheme) Name() string                                      { return d.n }
func (d *dummyScheme) Type() string                                      { return "custom" }
func (d *dummyScheme) Description() string                               { return "dummy" }
func (d *dummyScheme) Authenticate(r *http.Request) (interface{}, error) { return nil, nil }
func (d *dummyScheme) Challenge() string                                 { return "Custom" }

func TestWithScheme_CustomScheme(t *testing.T) {
	cfg := security.NewConfig(security.WithScheme(&dummyScheme{n: "custom"}))
	if len(cfg.Schemes) != 1 {
		t.Fatalf("expected 1 scheme, got %d", len(cfg.Schemes))
	}
	if cfg.Schemes[0].Name() != "custom" {
		t.Fatalf("expected scheme name 'custom', got %q", cfg.Schemes[0].Name())
	}
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	security "github.com/kryovyx/rextension-security"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// stubRegistrar is a minimal WebAuthnRegistrar for tests.
type stubRegistrar struct {
	beginOpts *security.PublicKeyCredentialCreationOptions
	beginErr  error
	finishErr error
}

func (r *stubRegistrar) BeginRegistration(_ context.Context, _ []byte, _ string) (*security.PublicKeyCredentialCreationOptions, error) {
	return r.beginOpts, r.beginErr
}

func (r *stubRegistrar) FinishRegistration(_ context.Context, _ []byte, _, _, _ []byte) error {
	return r.finishErr
}

// stubAuthenticator is a minimal WebAuthnAuthenticator for tests.
type stubAuthenticator struct {
	beginOpts *security.PublicKeyCredentialRequestOptions
	beginErr  error
	principal interface{}
	finishErr error
}

func (a *stubAuthenticator) BeginAuthentication(_ context.Context, _ []byte) (*security.PublicKeyCredentialRequestOptions, error) {
	return a.beginOpts, a.beginErr
}

func (a *stubAuthenticator) FinishAuthentication(_ context.Context, _ *security.AuthenticatorAssertionResponse) (interface{}, error) {
	return a.principal, a.finishErr
}

// ---------------------------------------------------------------------------
// NewWebAuthnScheme
// ---------------------------------------------------------------------------

func TestNewWebAuthnScheme_DefaultName(t *testing.T) {
	s := security.NewWebAuthnScheme("", nil, &stubAuthenticator{})
	if s.Name() != "webauthn" {
		t.Fatalf("expected default name 'webauthn', got %q", s.Name())
	}
}

func TestNewWebAuthnScheme_CustomName(t *testing.T) {
	s := security.NewWebAuthnScheme("passkey", nil, &stubAuthenticator{})
	if s.Name() != "passkey" {
		t.Fatalf("expected name 'passkey', got %q", s.Name())
	}
}

func TestNewWebAuthnScheme_NilAuthenticatorPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when authenticator is nil")
		}
	}()
	security.NewWebAuthnScheme("webauthn", nil, nil)
}

// ---------------------------------------------------------------------------
// WebAuthnScheme — SecurityScheme interface methods
// ---------------------------------------------------------------------------

func TestWebAuthnScheme_Type(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{})
	if s.Type() != "http" {
		t.Fatalf("expected type 'http', got %q", s.Type())
	}
}

func TestWebAuthnScheme_DefaultDescription(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{})
	if s.Description() == "" {
		t.Fatal("expected non-empty default description")
	}
}

func TestWebAuthnScheme_SetDescription(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{})
	ret := s.SetDescription("my custom desc")
	if ret != s {
		t.Fatal("SetDescription should return the same pointer for chaining")
	}
	if s.Description() != "my custom desc" {
		t.Fatalf("expected 'my custom desc', got %q", s.Description())
	}
}

func TestWebAuthnScheme_Challenge_Empty(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{})
	if s.Challenge() != "" {
		t.Fatalf("expected empty challenge, got %q", s.Challenge())
	}
}

func TestWebAuthnScheme_Registrar(t *testing.T) {
	reg := &stubRegistrar{}
	s := security.NewWebAuthnScheme("webauthn", reg, &stubAuthenticator{})
	if s.Registrar() != reg {
		t.Fatal("Registrar() did not return the supplied registrar")
	}
}

func TestWebAuthnScheme_Registrar_Nil(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{})
	if s.Registrar() != nil {
		t.Fatal("expected nil registrar when none supplied")
	}
}

func TestWebAuthnScheme_Authenticator(t *testing.T) {
	auth := &stubAuthenticator{}
	s := security.NewWebAuthnScheme("webauthn", nil, auth)
	if s.Authenticator() != auth {
		t.Fatal("Authenticator() did not return the supplied authenticator")
	}
}

// ---------------------------------------------------------------------------
// WebAuthnScheme.Authenticate
// ---------------------------------------------------------------------------

func TestWebAuthnScheme_Authenticate_NoResponseInContext(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{principal: "user1"})
	req := httptest.NewRequest(http.MethodPost, "/", nil)

	_, err := s.Authenticate(req)
	if err == nil {
		t.Fatal("expected error when no assertion response in context")
	}
}

func TestWebAuthnScheme_Authenticate_NilResponseInContext(t *testing.T) {
	s := security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{principal: "user1"})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := security.WithAssertionResponse(req.Context(), nil)
	req = req.WithContext(ctx)

	_, err := s.Authenticate(req)
	if err == nil {
		t.Fatal("expected error when nil assertion response in context")
	}
}

func TestWebAuthnScheme_Authenticate_AuthenticatorError(t *testing.T) {
	wantErr := errors.New("signature mismatch")
	auth := &stubAuthenticator{finishErr: wantErr}
	s := security.NewWebAuthnScheme("webauthn", nil, auth)

	resp := &security.AuthenticatorAssertionResponse{
		CredentialID: []byte("cred-id"),
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := security.WithAssertionResponse(req.Context(), resp)
	req = req.WithContext(ctx)

	_, err := s.Authenticate(req)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
}

func TestWebAuthnScheme_Authenticate_Success(t *testing.T) {
	auth := &stubAuthenticator{principal: "alice"}
	s := security.NewWebAuthnScheme("webauthn", nil, auth)

	resp := &security.AuthenticatorAssertionResponse{
		CredentialID:      []byte("cred-id"),
		ClientDataJSON:    []byte(`{"type":"webauthn.get"}`),
		AuthenticatorData: []byte{0x01},
		Signature:         []byte{0x02},
	}
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	ctx := security.WithAssertionResponse(req.Context(), resp)
	req = req.WithContext(ctx)

	principal, err := s.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "alice" {
		t.Fatalf("expected principal 'alice', got %v", principal)
	}
}

// ---------------------------------------------------------------------------
// WithAssertionResponse
// ---------------------------------------------------------------------------

func TestWithAssertionResponse_RoundTrip(t *testing.T) {
	resp := &security.AuthenticatorAssertionResponse{
		CredentialID: []byte("id-bytes"),
		UserHandle:   []byte("user-handle"),
	}
	ctx := security.WithAssertionResponse(context.Background(), resp)

	auth := &stubAuthenticator{principal: "bob"}
	s := security.NewWebAuthnScheme("webauthn", nil, auth)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(ctx)

	principal, err := s.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != "bob" {
		t.Fatalf("expected 'bob', got %v", principal)
	}
}

// ---------------------------------------------------------------------------
// WebAuthnScheme implements SecurityScheme interface (compile-time check)
// ---------------------------------------------------------------------------

func TestWebAuthnScheme_ImplementsSecurityScheme(t *testing.T) {
	var _ security.SecurityScheme = security.NewWebAuthnScheme("webauthn", nil, &stubAuthenticator{})
}

// ---------------------------------------------------------------------------
// stub interface compliance (compile-time checks)
// ---------------------------------------------------------------------------

var _ security.WebAuthnRegistrar = (*stubRegistrar)(nil)
var _ security.WebAuthnAuthenticator = (*stubAuthenticator)(nil)

// ---------------------------------------------------------------------------
// PublicKeyCredentialCreationOptions field access
// ---------------------------------------------------------------------------

func TestPublicKeyCredentialCreationOptions_Fields(t *testing.T) {
	opts := &security.PublicKeyCredentialCreationOptions{
		Challenge:       []byte("challenge-bytes"),
		RPID:            "example.com",
		RPName:          "Example",
		UserID:          []byte("uid"),
		UserName:        "alice",
		UserDisplayName: "Alice",
		Algorithms:      []security.WebAuthnAlgorithm{security.AlgES256, security.AlgRS256},
	}

	if string(opts.Challenge) != "challenge-bytes" {
		t.Fatalf("unexpected Challenge: %v", opts.Challenge)
	}
	if opts.RPID != "example.com" {
		t.Fatalf("unexpected RPID: %q", opts.RPID)
	}
	if len(opts.Algorithms) != 2 {
		t.Fatalf("expected 2 algorithms, got %d", len(opts.Algorithms))
	}
	if opts.Algorithms[0] != security.AlgES256 {
		t.Fatalf("expected AlgES256, got %v", opts.Algorithms[0])
	}
}

// ---------------------------------------------------------------------------
// PublicKeyCredentialRequestOptions field access
// ---------------------------------------------------------------------------

func TestPublicKeyCredentialRequestOptions_Fields(t *testing.T) {
	opts := &security.PublicKeyCredentialRequestOptions{
		Challenge:            []byte("req-challenge"),
		RPID:                 "example.com",
		AllowedCredentialIDs: [][]byte{[]byte("cred-1"), []byte("cred-2")},
	}

	if string(opts.Challenge) != "req-challenge" {
		t.Fatalf("unexpected Challenge: %v", opts.Challenge)
	}
	if len(opts.AllowedCredentialIDs) != 2 {
		t.Fatalf("expected 2 allowed credentials, got %d", len(opts.AllowedCredentialIDs))
	}
}

// ---------------------------------------------------------------------------
// PublicKeyCredentialRequestOptions — empty AllowedCredentialIDs (passkey flow)
// ---------------------------------------------------------------------------

func TestPublicKeyCredentialRequestOptions_EmptyAllowedCredentials(t *testing.T) {
	opts := &security.PublicKeyCredentialRequestOptions{
		Challenge: []byte("req-challenge"),
		RPID:      "example.com",
	}
	if len(opts.AllowedCredentialIDs) != 0 {
		t.Fatalf("expected empty AllowedCredentialIDs for passkey flow, got %d", len(opts.AllowedCredentialIDs))
	}
}

// ---------------------------------------------------------------------------
// AuthenticatorAssertionResponse field access
// ---------------------------------------------------------------------------

func TestAuthenticatorAssertionResponse_Fields(t *testing.T) {
	resp := &security.AuthenticatorAssertionResponse{
		CredentialID:      []byte("cred"),
		ClientDataJSON:    []byte("{}"),
		AuthenticatorData: []byte{0xAB},
		Signature:         []byte{0xCD},
		UserHandle:        []byte("user"),
	}

	if string(resp.CredentialID) != "cred" {
		t.Fatalf("unexpected CredentialID: %v", resp.CredentialID)
	}
	if resp.AuthenticatorData[0] != 0xAB {
		t.Fatalf("unexpected AuthenticatorData byte")
	}
	if resp.Signature[0] != 0xCD {
		t.Fatalf("unexpected Signature byte")
	}
	if string(resp.UserHandle) != "user" {
		t.Fatalf("unexpected UserHandle: %v", resp.UserHandle)
	}
}

// ---------------------------------------------------------------------------
// Algorithm constants
// ---------------------------------------------------------------------------

func TestWebAuthnAlgorithm_Values(t *testing.T) {
	tests := []struct {
		alg  security.WebAuthnAlgorithm
		want int32
	}{
		{security.AlgES256, -7},
		{security.AlgES384, -35},
		{security.AlgES512, -36},
		{security.AlgRS256, -257},
		{security.AlgEdDSA, -8},
	}
	for _, tc := range tests {
		if int32(tc.alg) != tc.want {
			t.Errorf("algorithm %v: expected COSE value %d, got %d", tc.alg, tc.want, int32(tc.alg))
		}
	}
}

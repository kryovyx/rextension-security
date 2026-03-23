// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the SecurityScheme interface and built-in implementations
// for Bearer token, Basic auth, and API key authentication.
package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// SecurityScheme defines an authentication strategy.
// Each scheme knows how to extract credentials from an HTTP request and
// validate them using a user-supplied callback.
type SecurityScheme interface {
	// Name returns a unique identifier for this scheme (e.g., "bearer", "basic").
	Name() string
	// Type returns the OpenAPI security scheme type (e.g., "http", "apiKey").
	Type() string
	// Description returns a description for the security scheme (used in OpenAPI).
	Description() string
	// Authenticate extracts credentials from the request and validates them.
	// On success it returns a principal (any value representing the authenticated
	// identity). On failure it returns an error.
	Authenticate(r *http.Request) (principal interface{}, err error)
	// Challenge returns the WWW-Authenticate header value for 401 responses.
	Challenge() string
}

// --- Bearer Token Scheme ---

// BearerValidateFunc is the callback signature for Bearer token validation.
// It receives the raw token string and returns a principal or error.
type BearerValidateFunc func(token string) (principal interface{}, err error)

// BearerScheme authenticates via the Authorization: Bearer <token> header.
type BearerScheme struct {
	name         string
	description  string
	bearerFormat string
	validate     BearerValidateFunc
}

// NewBearerScheme creates a Bearer authentication scheme.
func NewBearerScheme(name string, validate BearerValidateFunc) *BearerScheme {
	if name == "" {
		name = "bearer"
	}
	return &BearerScheme{
		name:         name,
		description:  "Bearer token authentication",
		bearerFormat: "JWT",
		validate:     validate,
	}
}

func (s *BearerScheme) Name() string        { return s.name }
func (s *BearerScheme) Type() string        { return "http" }
func (s *BearerScheme) Description() string { return s.description }

// BearerFormat returns the bearer format (e.g., "JWT").
func (s *BearerScheme) BearerFormat() string { return s.bearerFormat }

// SetBearerFormat sets the bearer format (e.g., "JWT", "custom").
func (s *BearerScheme) SetBearerFormat(fmt string) *BearerScheme {
	s.bearerFormat = fmt
	return s
}

// SetDescription sets the description for OpenAPI documentation.
func (s *BearerScheme) SetDescription(desc string) *BearerScheme {
	s.description = desc
	return s
}

func (s *BearerScheme) Authenticate(r *http.Request) (interface{}, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("authorization header is not Bearer")
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return nil, fmt.Errorf("empty bearer token")
	}
	return s.validate(token)
}

func (s *BearerScheme) Challenge() string {
	return "Bearer"
}

// --- Basic Auth Scheme ---

// BasicValidateFunc is the callback signature for Basic auth validation.
type BasicValidateFunc func(username, password string) (principal interface{}, err error)

// BasicScheme authenticates via the Authorization: Basic <base64> header.
type BasicScheme struct {
	name     string
	realm    string
	validate BasicValidateFunc
}

// NewBasicScheme creates a Basic authentication scheme.
func NewBasicScheme(name, realm string, validate BasicValidateFunc) *BasicScheme {
	if name == "" {
		name = "basic"
	}
	if realm == "" {
		realm = "Restricted"
	}
	return &BasicScheme{name: name, realm: realm, validate: validate}
}

func (s *BasicScheme) Name() string { return s.name }
func (s *BasicScheme) Type() string { return "http" }
func (s *BasicScheme) Description() string {
	return fmt.Sprintf("HTTP Basic authentication (realm: %s)", s.realm)
}

func (s *BasicScheme) Authenticate(r *http.Request) (interface{}, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("authorization header is not Basic")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in Basic auth: %w", err)
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Basic auth format")
	}
	return s.validate(parts[0], parts[1])
}

func (s *BasicScheme) Challenge() string {
	return fmt.Sprintf("Basic realm=%q", s.realm)
}

// --- API Key Scheme ---

// APIKeyLocation defines where the API key is expected.
type APIKeyLocation string

const (
	// APIKeyHeader expects the key in an HTTP header.
	APIKeyHeader APIKeyLocation = "header"
	// APIKeyQuery expects the key in a query parameter.
	APIKeyQuery APIKeyLocation = "query"
	// APIKeyCookie expects the key as an HTTP cookie.
	// Use this location for BFF session cookies (OpenAPI in: cookie).
	APIKeyCookie APIKeyLocation = "cookie"
)

// APIKeyValidateFunc is the callback signature for API key validation.
type APIKeyValidateFunc func(key string) (principal interface{}, err error)

// APIKeyScheme authenticates via a named header or query parameter.
type APIKeyScheme struct {
	name      string
	paramName string
	location  APIKeyLocation
	validate  APIKeyValidateFunc
}

// NewAPIKeyScheme creates an API key authentication scheme.
// paramName is the header or query parameter name (e.g., "X-API-Key").
func NewAPIKeyScheme(name, paramName string, location APIKeyLocation, validate APIKeyValidateFunc) *APIKeyScheme {
	if name == "" {
		name = "apikey"
	}
	return &APIKeyScheme{
		name:      name,
		paramName: paramName,
		location:  location,
		validate:  validate,
	}
}

func (s *APIKeyScheme) Name() string { return s.name }
func (s *APIKeyScheme) Type() string { return "apiKey" }
func (s *APIKeyScheme) Description() string {
	return fmt.Sprintf("API key provided in %s parameter '%s'", s.location, s.paramName)
}

// ParamName returns the header or query parameter name.
func (s *APIKeyScheme) ParamName() string { return s.paramName }

// Location returns where the API key is expected (header or query).
func (s *APIKeyScheme) Location() APIKeyLocation { return s.location }

func (s *APIKeyScheme) Authenticate(r *http.Request) (interface{}, error) {
	var key string
	switch s.location {
	case APIKeyHeader:
		key = r.Header.Get(s.paramName)
	case APIKeyQuery:
		key = r.URL.Query().Get(s.paramName)
	case APIKeyCookie:
		c, err := r.Cookie(s.paramName)
		if err != nil {
			return nil, fmt.Errorf("missing cookie %q", s.paramName)
		}
		key = c.Value
	default:
		return nil, fmt.Errorf("unknown API key location: %s", s.location)
	}
	if key == "" {
		return nil, fmt.Errorf("missing API key in %s %q", s.location, s.paramName)
	}
	return s.validate(key)
}

func (s *APIKeyScheme) Challenge() string {
	return fmt.Sprintf("ApiKey name=%q, in=%q", s.paramName, s.location)
}

// --- Session Cookie Scheme ---

// SessionValidateFunc is the callback signature for session cookie validation.
// It receives the raw session ID extracted from the cookie and must return
// the principal (e.g. a user object, claims map) that represents the
// authenticated session, or an error if the session is unknown or expired.
//
// The function is responsible for any OAuth token exchange, cache lookup, or
// database query needed to resolve the session ID to a principal.
// It is optional when a SessionStore is attached via WithStore — in that case
// the store's Get method is used instead.
type SessionValidateFunc func(sessionID string) (principal interface{}, err error)

// CookieOptions controls the attributes of the Set-Cookie header written by
// IssueSession. Use WithCookieOptions to configure these on a scheme.
type CookieOptions struct {
	// MaxAge is the cookie lifetime in seconds. 0 means a session cookie
	// (deleted when the browser closes). Negative values delete the cookie.
	MaxAge int
	// Path is the cookie path attribute. Defaults to "/" when left empty.
	Path string
	// Domain is the optional cookie domain attribute.
	Domain string
	// Secure instructs the browser to only send the cookie over HTTPS.
	// Always set to true in production.
	Secure bool
	// HttpOnly prevents JavaScript from accessing the cookie (XSS mitigation).
	// Defaults to true.
	HttpOnly bool
	// SameSite controls cross-site cookie behaviour.
	// Defaults to http.SameSiteLaxMode when zero.
	SameSite http.SameSite
}

// SessionCookieScheme authenticates requests via an HTTP session cookie.
// It is designed for Backend-For-Frontend (BFF) services where the server
// manages user sessions internally and the client only ever sees a short-lived
// opaque session cookie.
//
// The scheme maps to OpenAPI 3.0 type "apiKey" with "in: cookie", which is
// the specification-correct representation of a cookie-based API key.
//
// Session lifecycle:
//   - Call IssueSession from a login handler to create a session and write
//     the Set-Cookie header.
//   - The middleware calls Authenticate on every protected request, which
//     resolves the session via the attached SessionStore or validate func.
//   - Call RevokeSession from a logout handler to delete the session and
//     clear the cookie.
type SessionCookieScheme struct {
	name          string
	cookieName    string
	description   string
	validate      SessionValidateFunc
	store         SessionStore
	cookieOptions CookieOptions
}

// NewSessionCookieScheme creates a session-cookie authentication scheme.
// name is the unique scheme identifier registered with the security extension.
// cookieName is the HTTP cookie name that carries the session ID (e.g. "session_id").
// validate is called with the raw cookie value on every authenticated request
// when no SessionStore is attached. Pass nil when you intend to call WithStore.
func NewSessionCookieScheme(name, cookieName string, validate SessionValidateFunc) *SessionCookieScheme {
	if name == "" {
		name = "sessionCookie"
	}
	if cookieName == "" {
		cookieName = "session_id"
	}
	return &SessionCookieScheme{
		name:        name,
		cookieName:  cookieName,
		description: fmt.Sprintf("Session cookie authentication via cookie %q", cookieName),
		validate:    validate,
		cookieOptions: CookieOptions{
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}
}

func (s *SessionCookieScheme) Name() string        { return s.name }
func (s *SessionCookieScheme) Type() string        { return "apiKey" }
func (s *SessionCookieScheme) Description() string { return s.description }

// CookieName returns the name of the HTTP cookie that carries the session ID.
func (s *SessionCookieScheme) CookieName() string { return s.cookieName }

// ParamName returns the cookie name; satisfies the OpenAPI generator duck-type
// interface{ ParamName() string; Location() string }.
func (s *SessionCookieScheme) ParamName() string { return s.cookieName }

// Location returns "cookie" to satisfy the OpenAPI generator duck-type interface
// and produce a correct "in: cookie" entry in the OpenAPI document.
func (s *SessionCookieScheme) Location() string { return "cookie" }

// SetDescription sets the description for OpenAPI documentation.
func (s *SessionCookieScheme) SetDescription(desc string) *SessionCookieScheme {
	s.description = desc
	return s
}

// WithStore attaches a SessionStore to the scheme.
// When a store is attached, Authenticate calls store.Get(ctx, sessionID)
// instead of the validate func, and IssueSession / RevokeSession become
// available for the login and logout handlers.
func (s *SessionCookieScheme) WithStore(store SessionStore) *SessionCookieScheme {
	s.store = store
	return s
}

// WithCookieOptions replaces the cookie attributes used by IssueSession.
// By default HttpOnly is true and SameSite is Lax.
func (s *SessionCookieScheme) WithCookieOptions(opts CookieOptions) *SessionCookieScheme {
	s.cookieOptions = opts
	return s
}

// IssueSession generates a cryptographically random session ID, persists the
// principal in the attached SessionStore, and writes a Set-Cookie header on w.
// It returns the new session ID so the caller can use it for further work
// (e.g. storing it in an audit log).
//
// IssueSession requires a SessionStore to be attached via WithStore.
func (s *SessionCookieScheme) IssueSession(ctx context.Context, w http.ResponseWriter, principal interface{}) (string, error) {
	if s.store == nil {
		return "", fmt.Errorf("SessionCookieScheme: no SessionStore attached — call WithStore first")
	}
	// Generate 32 cryptographically random bytes → 64-character hex session ID.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("SessionCookieScheme: failed to generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(b)

	if err := s.store.Set(ctx, sessionID, principal); err != nil {
		return "", fmt.Errorf("SessionCookieScheme: failed to store session: %w", err)
	}

	opts := s.cookieOptions
	path := opts.Path
	if path == "" {
		path = "/"
	}
	sameSite := opts.SameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    sessionID,
		MaxAge:   opts.MaxAge,
		Path:     path,
		Domain:   opts.Domain,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: sameSite,
	})
	return sessionID, nil
}

// RevokeSession reads the session cookie from the request, removes the session
// from the attached SessionStore, and clears the cookie in the response.
// If the cookie is absent it is a no-op (the session was already gone).
// If no store is attached the cookie is still cleared on the response.
func (s *SessionCookieScheme) RevokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		// Cookie not present — nothing to revoke.
		return nil
	}
	if s.store != nil && c.Value != "" {
		if err := s.store.Delete(ctx, c.Value); err != nil {
			return fmt.Errorf("SessionCookieScheme: failed to delete session: %w", err)
		}
	}
	// Expire the cookie in the browser.
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *SessionCookieScheme) Authenticate(r *http.Request) (interface{}, error) {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil, fmt.Errorf("missing session cookie %q", s.cookieName)
	}
	sessionID := c.Value
	if sessionID == "" {
		return nil, fmt.Errorf("empty session cookie %q", s.cookieName)
	}
	// If a store is attached it is the authoritative source of truth.
	if s.store != nil {
		return s.store.Get(r.Context(), sessionID)
	}
	// Fall back to a user-supplied validate func (stateless validation).
	if s.validate == nil {
		return nil, fmt.Errorf("SessionCookieScheme: no store or validate func configured")
	}
	return s.validate(sessionID)
}

// Challenge intentionally returns an empty string.
// Session-cookie BFF services typically redirect to a login page on 401
// rather than issuing a WWW-Authenticate challenge, so no challenge header
// is emitted.
func (s *SessionCookieScheme) Challenge() string { return "" }

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
)

// CookieOptions controls the attributes of the Set-Cookie header written by
// SessionCookieScheme.IssueSession. Use WithCookieOptions to configure these.
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
//     resolves the session via the attached SessionStore or SessionValidator.
//   - Call RevokeSession from a logout handler to delete the session and
//     clear the cookie.
type SessionCookieScheme struct {
	name          string
	cookieName    string
	description   string
	validate      SessionValidator
	store         SessionStore
	cookieOptions CookieOptions
}

// NewSessionCookieScheme creates a session-cookie authentication scheme.
// name is the unique scheme identifier registered with the security extension.
// cookieName is the HTTP cookie name that carries the session ID (e.g. "session_id").
// validate is the SessionValidator used to authenticate requests when no
// SessionStore is attached via WithStore. Pass nil when using WithStore only.
// Use SessionValidateFunc to wrap a plain function:
//
// security.SessionValidateFunc(func(id string) (interface{}, error) { ... })
func NewSessionCookieScheme(name, cookieName string, validate SessionValidator) *SessionCookieScheme {
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
// instead of the SessionValidator, and IssueSession / RevokeSession use the
// store for session persistence.
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

// IssueSession creates a new session for principal and writes a Set-Cookie
// header on w. It returns the session ID.
//
// When a SessionStore is attached via WithStore, IssueSession generates a
// cryptographically random 64-hex-character session ID and persists the
// principal in the store.
//
// When a SessionValidator is passed to NewSessionCookieScheme, IssueSession
// delegates ID generation and storage to validator.IssueSession.
//
// At least one of a SessionStore or a SessionValidator must be configured.
func (s *SessionCookieScheme) IssueSession(ctx context.Context, w http.ResponseWriter, principal interface{}) (string, error) {
	var sessionID string
	if s.store != nil {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("SessionCookieScheme: failed to generate session ID: %w", err)
		}
		sessionID = hex.EncodeToString(b)
		if err := s.store.Set(ctx, sessionID, principal); err != nil {
			return "", fmt.Errorf("SessionCookieScheme: failed to store session: %w", err)
		}
	} else if s.validate != nil {
		var err error
		sessionID, err = s.validate.IssueSession(ctx, principal)
		if err != nil {
			return "", fmt.Errorf("SessionCookieScheme: validator failed to issue session: %w", err)
		}
	} else {
		return "", fmt.Errorf("SessionCookieScheme: no SessionStore attached — call WithStore first")
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
// from the attached SessionStore or via the SessionValidator, and clears the
// cookie in the response. If the cookie is absent it is a no-op.
func (s *SessionCookieScheme) RevokeSession(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil
	}
	if c.Value != "" {
		if s.store != nil {
			if err := s.store.Delete(ctx, c.Value); err != nil {
				return fmt.Errorf("SessionCookieScheme: failed to delete session: %w", err)
			}
		} else if s.validate != nil {
			if err := s.validate.RevokeSession(ctx, c.Value); err != nil {
				return fmt.Errorf("SessionCookieScheme: validator failed to revoke session: %w", err)
			}
		}
	}
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
	if s.store != nil {
		return s.store.Get(r.Context(), sessionID)
	}
	if s.validate == nil {
		return nil, fmt.Errorf("SessionCookieScheme: no store or validate func configured")
	}
	return s.validate.ValidateSession(r.Context(), sessionID)
}

// Challenge intentionally returns an empty string.
// Session-cookie BFF services typically redirect to a login page on 401
// rather than issuing a WWW-Authenticate challenge, so no challenge header
// is emitted.
func (s *SessionCookieScheme) Challenge() string { return "" }

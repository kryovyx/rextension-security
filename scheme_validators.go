// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"context"
	"errors"
)

// Sentinel errors returned by SessionValidateFunc when IssueSession or
// RevokeSession are called — the function type only supports ValidateSession.
var (
	errFuncValidatorNoIssue  = errors.New("SessionValidateFunc: IssueSession not supported — attach a SessionStore via WithStore")
	errFuncValidatorNoRevoke = errors.New("SessionValidateFunc: RevokeSession not supported — attach a SessionStore via WithStore")
)

// ---------------------------------------------------------------------------
// Validator interfaces
// ---------------------------------------------------------------------------

// TokenValidator validates bearer tokens (JWT, opaque, etc.).
// Implementations encapsulate all key material, JWKS caches, or other
// verification state — none of that is visible through this interface.
//
// Usage:
//
//	type myTokenValidator struct{ jwks JWKSCache }
//	func (v *myTokenValidator) ValidateToken(token string) (interface{}, error) { ... }
//
//	scheme := security.NewBearerScheme("jwt", myValidator)
type TokenValidator interface {
	ValidateToken(token string) (principal interface{}, err error)
}

// KeyValidator validates API keys (static, rotatable, etc.).
// Implementations may use an in-memory lookup, database call, or cache —
// all hidden behind this single method.
//
// Usage:
//
//	scheme := security.NewAPIKeyScheme("apikey", "X-API-Key", security.APIKeyHeader, myKeyValidator)
type KeyValidator interface {
	ValidateKey(key string) (principal interface{}, err error)
}

// SessionValidator handles the full server-side session lifecycle.
// Implementations own the session store (memory, Redis, DB, etc.) as a
// private field — callers interact only via these methods.
//
// ValidateSession resolves a session ID to a principal.
// IssueSession persists a principal and returns a new session ID.
// RevokeSession deletes the session by ID.
//
// Usage:
//
//	validator := myapp.NewSessionValidator(redisStore)
//	scheme := security.NewSessionCookieScheme("bff", "session_id", nil).
//	    WithValidator(validator)
type SessionValidator interface {
	ValidateSession(ctx context.Context, sessionID string) (principal interface{}, err error)
	IssueSession(ctx context.Context, principal interface{}) (sessionID string, err error)
	RevokeSession(ctx context.Context, sessionID string) error
}

// ---------------------------------------------------------------------------
// Function-type adapters (backward compatibility)
// ---------------------------------------------------------------------------

// BearerValidateFunc is a function that implements TokenValidator.
// Existing code that passes a bare function to NewBearerScheme should be
// wrapped: security.BearerValidateFunc(myFunc).
type BearerValidateFunc func(token string) (principal interface{}, err error)

// ValidateToken calls the underlying function, satisfying TokenValidator.
func (f BearerValidateFunc) ValidateToken(token string) (interface{}, error) { return f(token) }

// APIKeyValidateFunc is a function that implements KeyValidator.
// Wrap existing bare functions: security.APIKeyValidateFunc(myFunc).
type APIKeyValidateFunc func(key string) (principal interface{}, err error)

// ValidateKey calls the underlying function, satisfying KeyValidator.
func (f APIKeyValidateFunc) ValidateKey(key string) (interface{}, error) { return f(key) }

// SessionValidateFunc is a function that wraps a bare session-ID-to-principal
// lookup.  It satisfies SessionValidator for the ValidateSession path only;
// IssueSession and RevokeSession return ErrNotSupported so that
// SessionCookieScheme's own store-based lifecycle is still used when a
// SessionStore is attached via WithStore.
type SessionValidateFunc func(sessionID string) (principal interface{}, err error)

// ValidateSession calls the underlying function.
func (f SessionValidateFunc) ValidateSession(_ context.Context, sessionID string) (interface{}, error) {
	return f(sessionID)
}

// IssueSession is not supported by a bare function; it always returns an error.
// Use WithStore on the scheme for full session lifecycle management.
func (f SessionValidateFunc) IssueSession(_ context.Context, _ interface{}) (string, error) {
	return "", errFuncValidatorNoIssue
}

// RevokeSession is not supported by a bare function; it always returns an error.
func (f SessionValidateFunc) RevokeSession(_ context.Context, _ string) error {
	return errFuncValidatorNoRevoke
}

// BasicValidateFunc is the callback signature for Basic auth validation.
type BasicValidateFunc func(username, password string) (principal interface{}, err error)

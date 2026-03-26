// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"context"
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
//	validator := security.NewSessionStoreValidator(redisStore)
//	scheme := security.NewSessionCookieScheme("bff", "session_id", validator)
type SessionValidator interface {
	ValidateSession(ctx context.Context, sessionID string) (principal interface{}, err error)
	IssueSession(ctx context.Context, principal interface{}) (sessionID string, err error)
	RevokeSession(ctx context.Context, sessionID string) error
}

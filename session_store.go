// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SessionStore is a storage abstraction for server-side session data.
// Implementations may use an in-memory map, Redis, a relational database, or
// any other storage that fits the application's requirements.
//
// Use NewSessionStoreValidator to wrap a SessionStore into a SessionValidator
// that can be passed to NewSessionCookieScheme.
type SessionStore interface {
	// Get retrieves the principal associated with sessionID.
	// Returns an error if the session does not exist or has expired.
	Get(ctx context.Context, sessionID string) (principal interface{}, err error)

	// Set stores principal under sessionID, overwriting any existing entry.
	Set(ctx context.Context, sessionID string, principal interface{}) error

	// Delete removes the session entry for sessionID.
	// Implementations should treat a missing key as a no-op (no error).
	Delete(ctx context.Context, sessionID string) error
}

// SessionStoreValidator wraps a SessionStore to satisfy the SessionValidator interface.
// It generates a cryptographically random 64-hex-character session ID in IssueSession.
//
// Usage:
//
//	validator := security.NewSessionStoreValidator(redisStore)
//	scheme := security.NewSessionCookieScheme("bff", "session_id", validator)
type SessionStoreValidator struct {
	store SessionStore
}

// NewSessionStoreValidator wraps store in a SessionValidator.
func NewSessionStoreValidator(store SessionStore) SessionValidator {
	return &SessionStoreValidator{store: store}
}

// ValidateSession resolves a session ID to the stored principal.
func (v *SessionStoreValidator) ValidateSession(ctx context.Context, sessionID string) (interface{}, error) {
	return v.store.Get(ctx, sessionID)
}

// IssueSession generates a cryptographically random 64-hex-character session ID,
// persists principal in the store, and returns the ID.
func (v *SessionStoreValidator) IssueSession(ctx context.Context, principal interface{}) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("SessionStoreValidator: failed to generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(b)
	if err := v.store.Set(ctx, sessionID, principal); err != nil {
		return "", fmt.Errorf("SessionStoreValidator: failed to store session: %w", err)
	}
	return sessionID, nil
}

// RevokeSession removes the session from the store.
func (v *SessionStoreValidator) RevokeSession(ctx context.Context, sessionID string) error {
	return v.store.Delete(ctx, sessionID)
}

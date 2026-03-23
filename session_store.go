// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import "context"

// SessionStore is an optional interface that can be used to back a
// SessionCookieScheme with a persistent or distributed session repository.
//
// Implementations may use an in-memory map, Redis, a relational database, or
// any other storage that fits the application's requirements.
//
// Usage: inject a SessionStore into the validate func you pass to
// NewSessionCookieScheme:
//
//	store := myapp.NewRedisSessionStore(redisClient)
//	scheme := security.NewSessionCookieScheme("session", "session_id",
//	    func(sessionID string) (interface{}, error) {
//	        return store.Get(context.Background(), sessionID)
//	    },
//	)
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

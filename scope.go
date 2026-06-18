// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the scope-related interfaces:
//   - ScopedSecuredRoute — optional route interface declaring required OAuth2/OIDC scopes
//   - ScopeValidator     — optional scheme/validator interface for enforcing those scopes
package security

import "net/http"

// ScopedSecuredRoute is an optional extension of SecuredRoute.
// Routes implementing this declare required OAuth2/OIDC scopes per security scheme.
//
// The middleware enforces scopes after scheme authentication succeeds. If the route
// also implements SecuredRoute and lists a scheme in RequiredSchemes, any scopes
// declared for that scheme in RequiredScopes are validated before the handler runs.
//
// The map key is the security scheme name (must match a name from RequiredSchemes).
// The value is the list of scopes that must ALL be present in the token.
//
// Example:
//
//	func (r *MyRoute) RequiredScopes() map[string][]string {
//	    return map[string][]string{"machineUserJWT": {"server-admin"}}
//	}
type ScopedSecuredRoute interface {
	RequiredScopes() map[string][]string
}

// ScopeValidator is an optional interface a SecurityScheme or TokenValidator may
// implement to enforce OAuth2/OIDC scopes after authentication succeeds.
//
// The security middleware calls ValidateScopes only when:
//  1. The route implements ScopedSecuredRoute and lists scopes for this scheme.
//  2. The scheme (or its inner validator) implements ScopeValidator.
//
// Schemes that do not implement ScopeValidator skip scope enforcement silently,
// preserving backward compatibility.
type ScopeValidator interface {
	ValidateScopes(r *http.Request, principal interface{}, requiredScopes []string) error
}

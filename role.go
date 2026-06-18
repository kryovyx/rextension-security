// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the role-related interfaces:
//   - RoleGuardedRoute — optional route interface declaring required roles per scheme
//   - RoleValidator     — optional scheme/validator interface for enforcing those roles
package security

import "net/http"

// RoleGuardedRoute is an optional extension of SecuredRoute.
// Routes implementing this declare required roles per security scheme.
//
// The middleware enforces roles after scheme authentication succeeds. If the route
// also implements SecuredRoute and lists a scheme in RequiredSchemes, any roles
// declared for that scheme in RequiredRoles are validated before the handler runs.
//
// The map key is the security scheme name (must match a name from RequiredSchemes).
// The value is the list of roles that must ALL be present in the token.
//
// Example:
//
//	func (r *MyRoute) RequiredRoles() map[string][]string {
//	    return map[string][]string{"machineUserJWT": {"schema:admin"}}
//	}
type RoleGuardedRoute interface {
	RequiredRoles() map[string][]string
}

// RoleValidator is an optional interface a SecurityScheme or TokenValidator may
// implement to enforce roles after authentication succeeds.
//
// Implementations are initialized with the JWT claim name where roles are stored
// and whether that claim is multi-valued (an array). The defaults are claim "roles"
// and multivalued true.
//
// The security middleware calls ValidateRoles only when:
//  1. The route implements RoleGuardedRoute and lists roles for this scheme.
//  2. The scheme (or its inner validator) implements RoleValidator.
//
// Schemes that do not implement RoleValidator skip role enforcement silently,
// preserving backward compatibility.
type RoleValidator interface {
	ValidateRoles(r *http.Request, principal interface{}, requiredRoles []string) error
}

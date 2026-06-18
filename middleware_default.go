// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file implements the security middleware that authenticates requests
// against the route's declared security schemes.
package security

import (
	"context"
	"net/http"
	"strings"

	rxroute "github.com/kryovyx/rextension/route"
)

// SecurityMiddleware creates a standard HTTP middleware that enforces
// authentication for routes implementing SecuredRoute.
func SecurityMiddleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rt, found := rxroute.GetMatchedRoute(r)
			if !found {
				next.ServeHTTP(w, r)
				return
			}

			sr, ok := rt.(SecuredRoute)
			if !ok {
				// Route does not declare security requirements.
				next.ServeHTTP(w, r)
				return
			}

			required := sr.RequiredSchemes()
			if len(required) == 0 {
				// Public route.
				next.ServeHTTP(w, r)
				return
			}

			// Try each required scheme. All must succeed.
			var challenges []string
			for _, schemeName := range required {
				scheme := cfg.SchemeRegistry.get(schemeName)
				if scheme == nil {
					http.Error(w, "500 Internal Server Error: unknown security scheme "+schemeName, http.StatusInternalServerError)
					return
				}

				principal, err := scheme.Authenticate(r)
				if err != nil {
					challenges = append(challenges, scheme.Challenge())
					// If any required scheme fails, return 401.
					w.Header().Set("WWW-Authenticate", strings.Join(challenges, ", "))
					http.Error(w, "401 Unauthorized: "+err.Error(), http.StatusUnauthorized)
					return
				}

				// Store the principal from this scheme.
				r = r.WithContext(context.WithValue(r.Context(), ContextKeyPrincipal, principal))
				r = r.WithContext(context.WithValue(r.Context(), ContextKeySchemeName, schemeName))

				// Scope enforcement (optional — only when the route declares scopes and
				// the scheme implements ScopeValidator).
				if scopedRoute, ok := sr.(ScopedSecuredRoute); ok {
					if scopes := scopedRoute.RequiredScopes()[schemeName]; len(scopes) > 0 {
						if sv, ok := scheme.(ScopeValidator); ok {
							if err := sv.ValidateScopes(r, principal, scopes); err != nil {
								http.Error(w, "403 Forbidden: "+err.Error(), http.StatusForbidden)
								return
							}
						}
					}
				}

				// Role enforcement (optional — only when the route declares roles and
				// the scheme implements RoleValidator).
				if roleRoute, ok := sr.(RoleGuardedRoute); ok {
					if roles := roleRoute.RequiredRoles()[schemeName]; len(roles) > 0 {
						if rv, ok := scheme.(RoleValidator); ok {
							if err := rv.ValidateRoles(r, principal, roles); err != nil {
								http.Error(w, "403 Forbidden: "+err.Error(), http.StatusForbidden)
								return
							}
						}
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

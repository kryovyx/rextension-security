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
)

// SecurityMiddleware creates a standard HTTP middleware that enforces
// authentication for routes implementing SecuredRoute.
func SecurityMiddleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sr, found := cfg.RouteIndex.lookup(r.Method, r.URL.Path)
			if !found {
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
			}

			next.ServeHTTP(w, r)
		})
	}
}

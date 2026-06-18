// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the middleware interfaces and the scheme registry.
package security

// Context keys for security data in request context.
type contextKey string

const (
	// ContextKeyPrincipal stores the authenticated principal.
	ContextKeyPrincipal contextKey = "security:principal"
	// ContextKeySchemeName stores the name of the scheme that authenticated the request.
	ContextKeySchemeName contextKey = "security:scheme_name"
)

// schemeRegistry holds the registered security schemes indexed by name.
type schemeRegistry struct {
	schemes map[string]SecurityScheme
	ordered []SecurityScheme
}

func newSchemeRegistry(schemes []SecurityScheme) *schemeRegistry {
	r := &schemeRegistry{
		schemes: make(map[string]SecurityScheme, len(schemes)),
		ordered: schemes,
	}
	for _, s := range schemes {
		r.schemes[s.Name()] = s
	}
	return r
}

func (r *schemeRegistry) get(name string) SecurityScheme {
	return r.schemes[name]
}

// all returns all registered security schemes in order.
func (r *schemeRegistry) all() []SecurityScheme {
	return r.ordered
}

// MiddlewareConfig holds runtime dependencies for the security middleware.
type MiddlewareConfig struct {
	SchemeRegistry *schemeRegistry
}

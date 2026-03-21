// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the middleware interfaces, route index, and context keys.
package security

import (
	"sync"

	rxevent "github.com/kryovyx/rextension/event"
)

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

// securedRouteIndex stores the SecuredRoute information for registered routes.
type securedRouteIndex struct {
	mu     sync.RWMutex
	routes map[string]SecuredRoute
}

func newSecuredRouteIndex() *securedRouteIndex {
	return &securedRouteIndex{routes: make(map[string]SecuredRoute)}
}

func (ri *securedRouteIndex) register(rt rxevent.Route) {
	if sr, ok := rt.(SecuredRoute); ok {
		key := rt.Method() + " " + rt.Path()
		ri.mu.Lock()
		ri.routes[key] = sr
		ri.mu.Unlock()
	}
}

func (ri *securedRouteIndex) lookup(method, path string) (SecuredRoute, bool) {
	key := method + " " + path
	ri.mu.RLock()
	sr, ok := ri.routes[key]
	ri.mu.RUnlock()
	return sr, ok
}

// MiddlewareConfig holds runtime dependencies for the security middleware.
type MiddlewareConfig struct {
	RouteIndex     *securedRouteIndex
	SchemeRegistry *schemeRegistry
}

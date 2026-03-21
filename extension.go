// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// The extension provides:
//   - Pluggable SecurityScheme interface for custom authentication
//   - Built-in Bearer, Basic, and API key schemes
//   - Per-route security requirements via the SecuredRoute interface
//   - Middleware that gates requests and stores the principal in context
//   - WWW-Authenticate challenge headers on 401 responses
package security

import (
	"context"

	rx "github.com/kryovyx/rextension"
	rxevent "github.com/kryovyx/rextension/event"
)

// SecurityExtension implements the Rex extension contract for authentication.
type SecurityExtension struct {
	cfg      Config
	logger   rx.Logger
	index    *securedRouteIndex
	registry *schemeRegistry
}

// NewSecurityExtension constructs a security extension instance.
func NewSecurityExtension(cfg *Config) rx.Extension {
	c := NewDefaultConfig()
	if cfg != nil {
		if len(cfg.Schemes) > 0 {
			c.Schemes = cfg.Schemes
		}
	}
	return &SecurityExtension{cfg: *c}
}

// WithSecurity is a helper Option to attach the security extension to Rex.
func WithSecurity(cfg *Config) rx.Option {
	return rx.WithExtension(NewSecurityExtension(cfg))
}

// OnInitialize sets up the security infrastructure and event subscriptions.
func (e *SecurityExtension) OnInitialize(ctx context.Context, r rx.Rex) error {
	e.logger = r.Logger()
	e.index = newSecuredRouteIndex()
	e.registry = newSchemeRegistry(e.cfg.Schemes)

	// Subscribe to route registration events to build the secured route index.
	r.EventBus().Subscribe(rxevent.EventTypeRouterRouteRegistered, func(ev rxevent.Event) {
			if routeEv, ok := rxevent.As[rxevent.RouterRouteRegisteredEvent](ev); ok {
			e.index.register(routeEv.Route)
			if sr, isSec := routeEv.Route.(SecuredRoute); isSec {
				e.logger.Info("Registered security for route %s %s: schemes=%v",
					routeEv.Route.Method(), routeEv.Route.Path(), sr.RequiredSchemes())
			}
		}
	})

	// Register the security middleware.
	mwCfg := MiddlewareConfig{
		RouteIndex:     e.index,
		SchemeRegistry: e.registry,
	}
	r.Use(SecurityMiddleware(mwCfg))

	// Expose the scheme registry and the extension itself via DI so other extensions
	// (e.g., OpenAPI) can access the schemes for documentation.
	r.Container().Instance(e.registry)
	r.Container().Instance(e) // Register self so OpenAPI can call Schemes()

	e.logger.Info("Security extension initialized with %d scheme(s)", len(e.cfg.Schemes))

	return nil
}

// OnStart publishes security schemes into the shared rextension registry so
// the OpenAPI extension (or any other extension) can read them without a
// direct import dependency on this module.
func (e *SecurityExtension) OnStart(ctx context.Context, r rx.Rex) error {
	if len(e.cfg.Schemes) > 0 {
		schemes := make([]rx.SecuritySchemeAccessor, len(e.cfg.Schemes))
		for i, s := range e.cfg.Schemes {
			schemes[i] = s // SecurityScheme satisfies rx.SecuritySchemeAccessor
		}
		rx.RegisterSecuritySchemes(schemes)
		e.logger.Info("Security: Registered %d schemes via rextension registry", len(schemes))
	}
	return nil
}

// OnReady is a no-op for the security extension.
func (e *SecurityExtension) OnReady(ctx context.Context, r rx.Rex) error { return nil }

// OnStop is a no-op for the security extension.
func (e *SecurityExtension) OnStop(ctx context.Context, r rx.Rex) error { return nil }

// OnShutdown is a no-op for the security extension.
func (e *SecurityExtension) OnShutdown(ctx context.Context, r rx.Rex) error { return nil }

// Schemes returns all registered security schemes. Used for documentation.
func (e *SecurityExtension) Schemes() []SecurityScheme {
	if e.registry == nil {
		return nil
	}
	return e.registry.all()
}

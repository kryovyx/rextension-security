// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the SecuredRoute interface that routes implement to declare
// their authentication requirements.
package security

// SecuredRoute is an optional interface that a route.Route may implement
// to declare which security schemes are required to access it.
//
// The security middleware type-asserts registered routes to this interface;
// routes that do not implement it are treated as public (no auth required).
type SecuredRoute interface {
	// RequiredSchemes returns the names of the security schemes that must
	// authenticate successfully before the handler is called.
	// An empty or nil slice means the route is public.
	RequiredSchemes() []string
}

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// Built-in scheme implementations live in their own files:
//   - scheme_bearer.go         — BearerScheme (Authorization: Bearer)
//   - scheme_basic.go          — BasicScheme  (Authorization: Basic)
//   - scheme_apikey.go         — APIKeyScheme (header / query / cookie)
//   - scheme_session_cookie.go — SessionCookieScheme (BFF session cookie)
//
// Validator interfaces and function-type adapters are in scheme_validators.go.
package security

import "net/http"

// SecurityScheme defines an authentication strategy.
// Each scheme knows how to extract credentials from an HTTP request and
// validate them using a user-supplied callback.
type SecurityScheme interface {
	// Name returns a unique identifier for this scheme (e.g., "bearer", "basic").
	Name() string
	// Type returns the OpenAPI security scheme type (e.g., "http", "apiKey").
	Type() string
	// Description returns a description for the security scheme (used in OpenAPI).
	Description() string
	// Authenticate extracts credentials from the request and validates them.
	// On success it returns a principal (any value representing the authenticated
	// identity). On failure it returns an error.
	Authenticate(r *http.Request) (principal interface{}, err error)
	// Challenge returns the WWW-Authenticate header value for 401 responses.
	Challenge() string
}

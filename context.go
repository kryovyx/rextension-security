// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file provides request context helpers for handlers to retrieve the
// authenticated principal and scheme information.
package security

import (
	"net/http"
)

// GetPrincipal retrieves the authenticated principal from the request context.
// Returns the principal and true if found, or nil and false otherwise.
func GetPrincipal(r *http.Request) (interface{}, bool) {
	val := r.Context().Value(ContextKeyPrincipal)
	return val, val != nil
}

// GetPrincipalAs retrieves the authenticated principal from the request context
// and type-asserts it to T. Returns the zero value and false if not found or
// if the type assertion fails.
func GetPrincipalAs[T any](r *http.Request) (T, bool) {
	val := r.Context().Value(ContextKeyPrincipal)
	if val == nil {
		var zero T
		return zero, false
	}
	typed, ok := val.(T)
	return typed, ok
}

// GetSchemeName retrieves the name of the security scheme that authenticated
// the request. Returns an empty string if the request was not authenticated.
func GetSchemeName(r *http.Request) string {
	val := r.Context().Value(ContextKeySchemeName)
	if val == nil {
		return ""
	}
	s, _ := val.(string)
	return s
}

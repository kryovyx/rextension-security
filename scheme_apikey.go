// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"fmt"
	"net/http"
)

// APIKeyLocation defines where the API key is expected.
type APIKeyLocation string

const (
	// APIKeyHeader expects the key in an HTTP header.
	APIKeyHeader APIKeyLocation = "header"
	// APIKeyQuery expects the key in a query parameter.
	APIKeyQuery APIKeyLocation = "query"
	// APIKeyCookie expects the key as an HTTP cookie.
	// Use this location for BFF session cookies (OpenAPI in: cookie).
	APIKeyCookie APIKeyLocation = "cookie"
)

// APIKeyScheme authenticates via a named header, query parameter, or cookie.
type APIKeyScheme struct {
	name      string
	paramName string
	location  APIKeyLocation
	validate  KeyValidator
}

// NewAPIKeyScheme creates an API key authentication scheme.
// paramName is the header or query parameter name (e.g., "X-API-Key").
// validate must implement KeyValidator.
func NewAPIKeyScheme(name, paramName string, location APIKeyLocation, validate KeyValidator) *APIKeyScheme {
	if name == "" {
		name = "apikey"
	}
	return &APIKeyScheme{
		name:      name,
		paramName: paramName,
		location:  location,
		validate:  validate,
	}
}

func (s *APIKeyScheme) Name() string { return s.name }
func (s *APIKeyScheme) Type() string { return "apiKey" }
func (s *APIKeyScheme) Description() string {
	return fmt.Sprintf("API key provided in %s parameter '%s'", s.location, s.paramName)
}

// ParamName returns the header or query parameter name.
func (s *APIKeyScheme) ParamName() string { return s.paramName }

// Location returns where the API key is expected (header, query, or cookie).
func (s *APIKeyScheme) Location() APIKeyLocation { return s.location }

func (s *APIKeyScheme) Authenticate(r *http.Request) (interface{}, error) {
	var key string
	switch s.location {
	case APIKeyHeader:
		key = r.Header.Get(s.paramName)
	case APIKeyQuery:
		key = r.URL.Query().Get(s.paramName)
	case APIKeyCookie:
		c, err := r.Cookie(s.paramName)
		if err != nil {
			return nil, fmt.Errorf("missing cookie %q", s.paramName)
		}
		key = c.Value
	default:
		return nil, fmt.Errorf("unknown API key location: %s", s.location)
	}
	if key == "" {
		return nil, fmt.Errorf("missing API key in %s %q", s.location, s.paramName)
	}
	return s.validate.ValidateKey(key)
}

func (s *APIKeyScheme) Challenge() string {
	return fmt.Sprintf("ApiKey name=%q, in=%q", s.paramName, s.location)
}

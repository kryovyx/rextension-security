// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the SecurityScheme interface and built-in implementations
// for Bearer token, Basic auth, and API key authentication.
package security

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

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

// --- Bearer Token Scheme ---

// BearerValidateFunc is the callback signature for Bearer token validation.
// It receives the raw token string and returns a principal or error.
type BearerValidateFunc func(token string) (principal interface{}, err error)

// BearerScheme authenticates via the Authorization: Bearer <token> header.
type BearerScheme struct {
	name         string
	description  string
	bearerFormat string
	validate     BearerValidateFunc
}

// NewBearerScheme creates a Bearer authentication scheme.
func NewBearerScheme(name string, validate BearerValidateFunc) *BearerScheme {
	if name == "" {
		name = "bearer"
	}
	return &BearerScheme{
		name:         name,
		description:  "Bearer token authentication",
		bearerFormat: "JWT",
		validate:     validate,
	}
}

func (s *BearerScheme) Name() string        { return s.name }
func (s *BearerScheme) Type() string        { return "http" }
func (s *BearerScheme) Description() string { return s.description }

// BearerFormat returns the bearer format (e.g., "JWT").
func (s *BearerScheme) BearerFormat() string { return s.bearerFormat }

// SetBearerFormat sets the bearer format (e.g., "JWT", "custom").
func (s *BearerScheme) SetBearerFormat(fmt string) *BearerScheme {
	s.bearerFormat = fmt
	return s
}

// SetDescription sets the description for OpenAPI documentation.
func (s *BearerScheme) SetDescription(desc string) *BearerScheme {
	s.description = desc
	return s
}

func (s *BearerScheme) Authenticate(r *http.Request) (interface{}, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("authorization header is not Bearer")
	}
	token := strings.TrimSpace(auth[len(prefix):])
	if token == "" {
		return nil, fmt.Errorf("empty bearer token")
	}
	return s.validate(token)
}

func (s *BearerScheme) Challenge() string {
	return "Bearer"
}

// --- Basic Auth Scheme ---

// BasicValidateFunc is the callback signature for Basic auth validation.
type BasicValidateFunc func(username, password string) (principal interface{}, err error)

// BasicScheme authenticates via the Authorization: Basic <base64> header.
type BasicScheme struct {
	name     string
	realm    string
	validate BasicValidateFunc
}

// NewBasicScheme creates a Basic authentication scheme.
func NewBasicScheme(name, realm string, validate BasicValidateFunc) *BasicScheme {
	if name == "" {
		name = "basic"
	}
	if realm == "" {
		realm = "Restricted"
	}
	return &BasicScheme{name: name, realm: realm, validate: validate}
}

func (s *BasicScheme) Name() string { return s.name }
func (s *BasicScheme) Type() string { return "http" }
func (s *BasicScheme) Description() string {
	return fmt.Sprintf("HTTP Basic authentication (realm: %s)", s.realm)
}

func (s *BasicScheme) Authenticate(r *http.Request) (interface{}, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return nil, fmt.Errorf("authorization header is not Basic")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in Basic auth: %w", err)
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Basic auth format")
	}
	return s.validate(parts[0], parts[1])
}

func (s *BasicScheme) Challenge() string {
	return fmt.Sprintf("Basic realm=%q", s.realm)
}

// --- API Key Scheme ---

// APIKeyLocation defines where the API key is expected.
type APIKeyLocation string

const (
	// APIKeyHeader expects the key in an HTTP header.
	APIKeyHeader APIKeyLocation = "header"
	// APIKeyQuery expects the key in a query parameter.
	APIKeyQuery APIKeyLocation = "query"
)

// APIKeyValidateFunc is the callback signature for API key validation.
type APIKeyValidateFunc func(key string) (principal interface{}, err error)

// APIKeyScheme authenticates via a named header or query parameter.
type APIKeyScheme struct {
	name      string
	paramName string
	location  APIKeyLocation
	validate  APIKeyValidateFunc
}

// NewAPIKeyScheme creates an API key authentication scheme.
// paramName is the header or query parameter name (e.g., "X-API-Key").
func NewAPIKeyScheme(name, paramName string, location APIKeyLocation, validate APIKeyValidateFunc) *APIKeyScheme {
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

// Location returns where the API key is expected (header or query).
func (s *APIKeyScheme) Location() APIKeyLocation { return s.location }

func (s *APIKeyScheme) Authenticate(r *http.Request) (interface{}, error) {
	var key string
	switch s.location {
	case APIKeyHeader:
		key = r.Header.Get(s.paramName)
	case APIKeyQuery:
		key = r.URL.Query().Get(s.paramName)
	default:
		return nil, fmt.Errorf("unknown API key location: %s", s.location)
	}
	if key == "" {
		return nil, fmt.Errorf("missing API key in %s %q", s.location, s.paramName)
	}
	return s.validate(key)
}

func (s *APIKeyScheme) Challenge() string {
	return fmt.Sprintf("ApiKey name=%q, in=%q", s.paramName, s.location)
}

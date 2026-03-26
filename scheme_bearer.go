// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"fmt"
	"net/http"
	"strings"
)

// BearerScheme authenticates via the Authorization: Bearer <token> header.
type BearerScheme struct {
	name         string
	description  string
	bearerFormat string
	validate     TokenValidator
}

// NewBearerScheme creates a Bearer authentication scheme.
// validate must implement TokenValidator.
func NewBearerScheme(name string, validate TokenValidator) *BearerScheme {
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
	return s.validate.ValidateToken(token)
}

func (s *BearerScheme) Challenge() string { return "Bearer" }

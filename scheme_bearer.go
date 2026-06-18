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
	rolesClaim   string
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

// SetRolesClaim sets the JWT claim name that carries role/permission values
// (e.g. "permissions", "realm_access.roles"). This is used purely for
// documentation purposes: the rextension-openapi generator emits it as
// x-roles-claim on the security scheme object so UI tooling can surface it.
func (s *BearerScheme) SetRolesClaim(claim string) *BearerScheme {
	s.rolesClaim = claim
	return s
}

// RolesClaim returns the configured JWT claim name for roles documentation.
// Implements the openapi.RoleClaimProvider interface (duck-typed, no import needed).
func (s *BearerScheme) RolesClaim() string { return s.rolesClaim }

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

// ValidateScopes implements ScopeValidator by delegating to the inner TokenValidator
// if it also implements ScopeValidator. Schemes whose validators do not implement
// ScopeValidator skip scope enforcement silently (backward compatible).
func (s *BearerScheme) ValidateScopes(r *http.Request, principal interface{}, requiredScopes []string) error {
	if sv, ok := s.validate.(ScopeValidator); ok {
		return sv.ValidateScopes(r, principal, requiredScopes)
	}
	return nil
}

// ValidateRoles implements RoleValidator by delegating to the inner TokenValidator
// if it also implements RoleValidator. Schemes whose validators do not implement
// RoleValidator skip role enforcement silently (backward compatible).
func (s *BearerScheme) ValidateRoles(r *http.Request, principal interface{}, requiredRoles []string) error {
	if rv, ok := s.validate.(RoleValidator); ok {
		return rv.ValidateRoles(r, principal, requiredRoles)
	}
	return nil
}

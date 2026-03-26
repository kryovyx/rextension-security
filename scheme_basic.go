// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// BasicValidateFunc is the callback signature for Basic auth credential validation.
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

// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

// Package security provides a Rex extension for authentication and authorization
// using pluggable security schemes.
//
// This file defines the extension configuration and functional options.
package security

// Config controls the security extension behavior.
type Config struct {
	// Schemes is the list of available security schemes.
	Schemes []SecurityScheme
}

// NewDefaultConfig returns an empty default configuration.
func NewDefaultConfig() *Config {
	return &Config{
		Schemes: []SecurityScheme{},
	}
}

// ConfigOption allows functional configuration.
type ConfigOption func(*Config)

// WithScheme registers a security scheme with the extension.
func WithScheme(s SecurityScheme) ConfigOption {
	return func(cfg *Config) {
		cfg.Schemes = append(cfg.Schemes, s)
	}
}

// NewConfig creates a config with the given options applied on top of defaults.
func NewConfig(opts ...ConfigOption) *Config {
	c := NewDefaultConfig()
	for _, opt := range opts {
		opt(c)
	}
	return c
}

package security

// NewTestMiddlewareConfig creates a MiddlewareConfig for use in external tests.
func NewTestMiddlewareConfig(schemes []SecurityScheme) MiddlewareConfig {
	return MiddlewareConfig{
		SchemeRegistry: newSchemeRegistry(schemes),
	}
}

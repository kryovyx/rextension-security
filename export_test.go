package security

import "github.com/kryovyx/rex/route"

// NewTestMiddlewareConfig creates a MiddlewareConfig for use in external tests.
func NewTestMiddlewareConfig(schemes []SecurityScheme, routes []route.Route) MiddlewareConfig {
	idx := newSecuredRouteIndex()
	for _, rt := range routes {
		idx.register(rt)
	}
	return MiddlewareConfig{
		RouteIndex:     idx,
		SchemeRegistry: newSchemeRegistry(schemes),
	}
}

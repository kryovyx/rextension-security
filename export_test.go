package security

import rxroute "github.com/kryovyx/rextension/route"

// NewTestMiddlewareConfig creates a MiddlewareConfig for use in external tests.
func NewTestMiddlewareConfig(schemes []SecurityScheme, routes []rxroute.Route) MiddlewareConfig {
	idx := newSecuredRouteIndex()
	for _, rt := range routes {
		idx.register(rt)
	}
	return MiddlewareConfig{
		RouteIndex:     idx,
		SchemeRegistry: newSchemeRegistry(schemes),
	}
}

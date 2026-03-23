# Rex Security Extension (rextension-security)

A pluggable authentication and authorization extension for the Rex framework.

[![Go Version](https://img.shields.io/badge/go-1.26+-blue.svg)](https://golang.org/dl/)
[![Coverage](https://img.shields.io/badge/coverage-83.2%25-green.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

`rextension-security` is a Rex extension that provides:

- **Pluggable SecurityScheme interface** for custom authentication strategies
- **Built-in schemes**: Bearer token, HTTP Basic, API key, and session cookie authentication
- **Per-route security requirements** via the `SecuredRoute` interface
- **Auto-registered middleware** that gates requests to secured routes
- **WWW-Authenticate challenge headers** on 401 responses
- **Context helpers** to retrieve the authenticated principal and scheme name
- **OpenAPI integration** via DI and the `rextension` global registry

## Installation

```bash
go get github.com/kryovyx/rextension-security
```

## Quick Start

```go
package main

import (
    "fmt"

    "github.com/kryovyx/rex"
    "github.com/kryovyx/rex/route"
    security "github.com/kryovyx/rextension-security"
)

func main() {
    app := rex.New()

    // Configure a Bearer token scheme
    bearer := security.NewBearerScheme("bearer", func(token string) (interface{}, error) {
        if token == "valid-token" {
            return map[string]string{"user": "admin"}, nil
        }
        return nil, fmt.Errorf("invalid token")
    })

    // Add security extension
    app.WithOptions(
        security.WithSecurity(security.NewConfig(
            security.WithScheme(bearer),
        )),
    )

    // Register a secured route
    app.RegisterRoute(&ProtectedRoute{})

    // Run the application
    if err := app.Run(); err != nil {
        panic(err)
    }
}

type ProtectedRoute struct{}

func (r *ProtectedRoute) Method() string      { return "GET" }
func (r *ProtectedRoute) Path() string        { return "/protected" }
func (r *ProtectedRoute) Handler() route.HandlerFunc {
    return func(ctx route.Context) {
        principal, _ := security.GetPrincipal(ctx.Request())
        ctx.JSON(200, map[string]interface{}{"principal": principal})
    }
}

// SecuredRoute implementation — requires the "bearer" scheme
func (r *ProtectedRoute) RequiredSchemes() []string {
    return []string{"bearer"}
}
```

## Security Schemes

### SecurityScheme Interface

All schemes implement the core `SecurityScheme` interface:

```go
type SecurityScheme interface {
    Name() string
    Type() string
    Description() string
    Authenticate(r *http.Request) (principal interface{}, err error)
    Challenge() string
}
```

### Bearer Token

Authenticates via the `Authorization: Bearer <token>` header.

```go
bearer := security.NewBearerScheme("bearer", func(token string) (interface{}, error) {
    // Validate the token (e.g., decode a JWT)
    claims, err := validateJWT(token)
    if err != nil {
        return nil, err
    }
    return claims, nil
})

// Optional: customize bearer format and description
bearer.SetBearerFormat("JWT")
bearer.SetDescription("JWT Bearer token authentication")
```

| Method               | Description                                      |
|----------------------|--------------------------------------------------|
| `NewBearerScheme(name, validateFunc)` | Creates a Bearer scheme             |
| `SetBearerFormat(fmt)`               | Sets the bearer format (default: `"JWT"`) |
| `SetDescription(desc)`              | Sets the description for OpenAPI docs     |

### HTTP Basic

Authenticates via the `Authorization: Basic <base64>` header.

```go
basic := security.NewBasicScheme("basic", "MyApp", func(username, password string) (interface{}, error) {
    if username == "admin" && password == "secret" {
        return map[string]string{"user": username, "role": "admin"}, nil
    }
    return nil, fmt.Errorf("invalid credentials")
})
```

| Method                                  | Description                                  |
|-----------------------------------------|----------------------------------------------|
| `NewBasicScheme(name, realm, validateFunc)` | Creates a Basic auth scheme              |

The `realm` parameter is included in the `WWW-Authenticate: Basic realm="..."` challenge header.

### API Key

Authenticates via a named header or query parameter.

```go
// API key in a header
apiKeyHeader := security.NewAPIKeyScheme("apikey", "X-API-Key", security.APIKeyHeader,
    func(key string) (interface{}, error) {
        if key == "my-secret-key" {
            return map[string]string{"client": "service-a"}, nil
        }
        return nil, fmt.Errorf("invalid API key")
    },
)

// API key in a query parameter
apiKeyQuery := security.NewAPIKeyScheme("apikey-query", "api_key", security.APIKeyQuery,
    func(key string) (interface{}, error) {
        // validate key...
        return nil, fmt.Errorf("invalid API key")
    },
)
```

| Method                                                  | Description                          |
|---------------------------------------------------------|--------------------------------------|
| `NewAPIKeyScheme(name, paramName, location, validateFunc)` | Creates an API key scheme         |

| Location Constant      | Description                                              |
|------------------------|----------------------------------------------------------|
| `security.APIKeyHeader` | Key expected in an HTTP header                         |
| `security.APIKeyQuery`  | Key expected in a query parameter                      |
| `security.APIKeyCookie` | Key expected as an HTTP cookie (BFF session cookie use case) |

## Secured Routes

Routes declare their authentication requirements by implementing the `SecuredRoute` interface:

```go
type SecuredRoute interface {
    RequiredSchemes() []string
}
```

The security middleware automatically type-asserts registered routes to this interface. Routes that do not implement it are treated as **public** (no authentication required).

```go
type AdminRoute struct{}

func (r *AdminRoute) Method() string      { return "DELETE" }
func (r *AdminRoute) Path() string        { return "/admin/users/:id" }
func (r *AdminRoute) Handler() route.HandlerFunc {
    return func(ctx route.Context) {
        user, _ := security.GetPrincipalAs[*User](ctx.Request())
        ctx.JSON(200, map[string]string{"deleted_by": user.Name})
    }
}

// Require both bearer and API key authentication
func (r *AdminRoute) RequiredSchemes() []string {
    return []string{"bearer", "apikey"}
}
```

When authentication fails, the middleware responds with `401 Unauthorized` and includes `WWW-Authenticate` challenge headers from the required schemes.

## Context Helpers

After successful authentication, the middleware stores the principal and scheme name in the request context. Use these helpers in your handlers:

### GetPrincipal

```go
principal, ok := security.GetPrincipal(r)
if !ok {
    // Not authenticated
}
```

Returns the authenticated principal (`interface{}`) and a boolean indicating whether it was found.

### GetPrincipalAs

```go
user, ok := security.GetPrincipalAs[*User](r)
if !ok {
    // Not authenticated or wrong type
}
fmt.Println(user.Name)
```

A generic helper that retrieves the principal and type-asserts it to `T`. Returns the zero value and `false` if not found or the type assertion fails.

### GetSchemeName

```go
scheme := security.GetSchemeName(r)
// e.g., "bearer", "basic", "apikey"
```

Returns the name of the security scheme that authenticated the request, or an empty string if unauthenticated.

## Configuration Reference

| Field     | Type               | Default | Description                          |
|-----------|--------------------|---------|--------------------------------------|
| `Schemes` | `[]SecurityScheme` | `[]`    | List of available security schemes   |

### Config Options

```go
security.WithSecurity(security.NewConfig(
    security.WithScheme(bearerScheme),
    security.WithScheme(apiKeyScheme),
))
```

| Option           | Description                                |
|------------------|--------------------------------------------|
| `WithScheme(s)`  | Registers a security scheme with the config|

## OpenAPI Integration

When used alongside `rextension-openapi`, security schemes are automatically documented in the OpenAPI spec:

- Schemes are published to the `rextension` global registry during `OnStart`
- The OpenAPI extension discovers schemes via DI and the global registry
- Routes implementing both `OpenAPIRoute` and `SecuredRoute` get `security` requirements in their operations
- Scheme metadata (`Name`, `Type`, `Description`, `BearerFormat`) maps to `components/securitySchemes`

No additional configuration is needed — just register both extensions and the integration is automatic.

## Best Practices

1. **Use meaningful scheme names**: Choose descriptive names like `"bearer"`, `"basic"`, `"api-key"` for clarity in logs and OpenAPI docs
2. **Validate tokens thoroughly**: Always verify token signatures, expiry, and claims in your validate functions
3. **Return rich principals**: Return structs with user details rather than plain strings for easier downstream use with `GetPrincipalAs`
4. **Handle multiple schemes carefully**: When a route requires multiple schemes, all must authenticate successfully
5. **Keep validate functions fast**: Authentication runs on every request to secured routes — avoid expensive operations or cache results
6. **Use appropriate scheme types**: Bearer for JWT/OAuth tokens, Basic for simple credentials, API Key for service-to-service auth, Session Cookie for BFF services
7. **Set descriptions for OpenAPI**: Use `SetDescription()` on schemes to provide clear documentation for API consumers
8. **Leverage type-safe principals**: Use `GetPrincipalAs[T]` instead of manual type assertions for cleaner handler code

### Session Cookie (BFF)

Designed for **Backend-For-Frontend** services: the BFF holds user sessions internally (backed by an OAuth system), and the browser only sees an opaque session cookie. Any internal OAuth token exchange or session-store lookup happens inside the `validate` function.

```go
// One shared scheme wired to a session store.
store := myapp.NewSessionStore()   // any SessionStore implementation
scheme := security.NewSessionCookieScheme("session", "session_id", nil).
    WithStore(store).
    WithCookieOptions(security.CookieOptions{
        HttpOnly: true,
        Secure:   true,   // always in production
        MaxAge:   3600,   // 1 hour
        Path:     "/",
    })

// Login handler — POST /auth/login
func (r *LoginRoute) Handler() route.HandlerFunc {
    return func(ctx route.Context) {
        // exchange credentials with OAuth server, receive principal
        principal, err := oauthClient.AuthenticateUser(username, password)
        if err != nil {
            ctx.JSON(401, dto.ErrorResponse{Error: "invalid credentials"})
            return
        }
        // creates session ID, calls store.Set, writes Set-Cookie
        if _, err := scheme.IssueSession(ctx.Request().Context(), ctx.ResponseWriter(), principal); err != nil {
            ctx.JSON(500, dto.ErrorResponse{Error: "could not create session"})
            return
        }
        ctx.JSON(200, dto.LoginResponse{Message: "logged in"})
    }
}

// Protected handler — GET /session/profile (requires "session" scheme)
func (r *SessionProfileRoute) Handler() route.HandlerFunc {
    return func(ctx route.Context) {
        // principal was resolved from the store by the middleware
        user, _ := security.GetPrincipalAs[*MyUser](ctx.Request())
        ctx.JSON(200, dto.ProfileResponse{Subject: user.Name})
    }
}
func (r *SessionProfileRoute) RequiredSchemes() []string { return []string{"session"} }

// Logout handler — DELETE /auth/logout
func (r *LogoutRoute) Handler() route.HandlerFunc {
    return func(ctx route.Context) {
        // removes from store, clears Set-Cookie in response
        scheme.RevokeSession(ctx.Request().Context(), ctx.ResponseWriter(), ctx.Request())
        ctx.JSON(200, dto.LogoutResponse{Message: "logged out"})
    }
}
```

The scheme produces the following OpenAPI entry:

```yaml
components:
  securitySchemes:
    session:
      type: apiKey
      in: cookie
      name: session_id
```

| Method | Description |
|---|---|
| `NewSessionCookieScheme(name, cookieName, validateFunc)` | Creates a session-cookie scheme (pass `nil` for validateFunc when using a store) |
| `CookieName()` | Returns the HTTP cookie name |
| `ParamName()` | Alias for `CookieName()`, used by the OpenAPI generator |
| `Location()` | Always returns `"cookie"`, satisfies the OpenAPI duck-type |
| `SetDescription(desc)` | Sets the description for OpenAPI docs |
| `WithStore(store)` | Attaches a SessionStore; Authenticate will use `store.Get` instead of the validate func |
| `WithCookieOptions(opts)` | Configures Set-Cookie attributes used by IssueSession |
| `IssueSession(ctx, w, principal)` | Generates a session ID, stores the principal, writes Set-Cookie |
| `RevokeSession(ctx, w, r)` | Deletes the session from the store and clears the cookie |

**CookieOptions fields:**

| Field | Type | Default | Description |
|---|---|---|---|
| `MaxAge` | `int` | `0` | Seconds until expiry; 0 = session cookie (deleted on browser close) |
| `Path` | `string` | `"/"` | Cookie path; defaults to `/` if empty |
| `Domain` | `string` | `""` | Cookie domain attribute (optional) |
| `Secure` | `bool` | `false` | Send only over HTTPS — set `true` in production |
| `HttpOnly` | `bool` | `true` | Prevent JavaScript access (mitigates XSS) |
| `SameSite` | `http.SameSite` | Lax | Cross-site cookie policy |

**SessionStore interface** — optionally use the `SessionStore` interface to decouple session-store logic:

```go
type SessionStore interface {
    Get(ctx context.Context, sessionID string) (principal interface{}, err error)
    Set(ctx context.Context, sessionID string, principal interface{}) error
    Delete(ctx context.Context, sessionID string) error
}
```

The interface is deliberately left without a built-in implementation so you can wire in Redis, a relational database, or an in-memory map that suits your deployment.

## Contributing

**At this time, this project is in active development and is not open for external contributions.** The framework is still being refined and major interfaces may change.

Once the framework reaches a stable architecture and API, contributions from the community will be welcome. Please check back later or open an issue if you have feature requests or feedback.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Copyright

© 2026 Kryovyx

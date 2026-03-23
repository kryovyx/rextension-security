// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: © 2026 Kryovyx

package security

import (
	"context"
	"fmt"
	"net/http"
)

// --- WebAuthn / FIDO2 types ---

// WebAuthnAlgorithm is a COSE algorithm identifier as defined in
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms.
// Only signing algorithms relevant to WebAuthn are listed here.
type WebAuthnAlgorithm int32

const (
	// AlgES256 is ECDSA w/ SHA-256 (COSE -7).
	AlgES256 WebAuthnAlgorithm = -7
	// AlgES384 is ECDSA w/ SHA-384 (COSE -35).
	AlgES384 WebAuthnAlgorithm = -35
	// AlgES512 is ECDSA w/ SHA-512 (COSE -36).
	AlgES512 WebAuthnAlgorithm = -36
	// AlgRS256 is RSASSA-PKCS1-v1_5 w/ SHA-256 (COSE -257).
	AlgRS256 WebAuthnAlgorithm = -257
	// AlgEdDSA is EdDSA (COSE -8).
	AlgEdDSA WebAuthnAlgorithm = -8
)

// PublicKeyCredentialCreationOptions is the subset of the W3C
// PublicKeyCredentialCreationOptions dictionary (§5.4) that is returned to the
// client to initiate a registration ceremony.
//
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions
type PublicKeyCredentialCreationOptions struct {
	// Challenge is a cryptographically random byte sequence (≥16 bytes) that
	// must be signed by the authenticator and returned in the attestation.
	Challenge []byte
	// RPID is the Relying Party identifier (e.g. "example.com").
	RPID string
	// RPName is the human-readable Relying Party name.
	RPName string
	// UserID is the opaque user handle (not a username; must be ≤64 bytes).
	UserID []byte
	// UserName is the human-readable account identifier displayed to the user.
	UserName string
	// UserDisplayName is a friendly display name for the user.
	UserDisplayName string
	// Algorithms is the ordered list of COSE algorithm identifiers acceptable
	// to the Relying Party. If empty, ES256 must be assumed by the caller.
	Algorithms []WebAuthnAlgorithm
}

// PublicKeyCredentialRequestOptions is the subset of the W3C
// PublicKeyCredentialRequestOptions dictionary (§5.5) returned to the client
// to initiate an authentication ceremony.
//
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions
type PublicKeyCredentialRequestOptions struct {
	// Challenge is a cryptographically random byte sequence (≥16 bytes) that
	// must be signed by the authenticator.
	Challenge []byte
	// RPID is the Relying Party identifier that the client will compare against
	// the origin.
	RPID string
	// AllowedCredentialIDs is the optional list of credential IDs acceptable
	// for this assertion. An empty list means any registered credential is
	// allowed (discoverable credential / passkey flow).
	AllowedCredentialIDs [][]byte
}

// AuthenticatorAssertionResponse is the client-side payload returned after a
// successful navigator.credentials.get() call.
//
// It maps to the AuthenticatorAssertionResponse interface defined in:
// https://www.w3.org/TR/webauthn-3/#iface-authenticatorassertionresponse
type AuthenticatorAssertionResponse struct {
	// CredentialID is the raw credential ID chosen by the authenticator.
	CredentialID []byte
	// ClientDataJSON is the UTF-8 serialised CollectedClientData.
	ClientDataJSON []byte
	// AuthenticatorData contains the authenticator data structure.
	AuthenticatorData []byte
	// Signature is the assertion signature produced by the private key.
	Signature []byte
	// UserHandle is the optional user handle returned by the authenticator.
	// Present for discoverable credentials (passkeys).
	UserHandle []byte
}

// --- WebAuthnRegistrar ---

// WebAuthnRegistrar handles the registration ceremony (§7.1 of the WebAuthn
// specification). It is responsible for challenge generation, credential
// storage, and public key persistence.
//
// Implementations decide how challenges are issued and stored (e.g. in a
// short-lived cache, encrypted cookie, or distributed session) and how
// credentials are persisted (e.g. database, key-value store).
type WebAuthnRegistrar interface {
	// BeginRegistration generates PublicKeyCredentialCreationOptions for the
	// user identified by userID and userName. The returned options must be
	// forwarded to the client as JSON.
	//
	// The implementation is responsible for issuing a challenge with
	// sufficient entropy (≥16 bytes, recommended ≥32 bytes) and for
	// associating it with the userID so it can be verified in
	// FinishRegistration.
	BeginRegistration(ctx context.Context, userID []byte, userName string) (*PublicKeyCredentialCreationOptions, error)

	// FinishRegistration verifies the attestation produced by the
	// authenticator, validates the challenge, and persists the new
	// credential (public key, credential ID, sign counter) for the user.
	//
	// credentialID is the raw credential ID returned by the browser.
	// clientDataJSON and attestationObject are the raw bytes from the
	// AuthenticatorAttestationResponse.
	//
	// On success the caller may return any value representing the newly
	// registered credential (e.g. a credential record, an ID string, or nil).
	FinishRegistration(ctx context.Context, userID []byte, credentialID, clientDataJSON, attestationObject []byte) error
}

// --- WebAuthnAuthenticator ---

// WebAuthnAuthenticator handles the authentication ceremony (§7.2 of the
// WebAuthn specification). It is responsible for challenge generation,
// signature verification, and sign-counter validation.
//
// Implementations decide how challenges are issued and stored (consistent with
// WebAuthnRegistrar) and how stored public keys and sign counters are
// retrieved and updated.
type WebAuthnAuthenticator interface {
	// BeginAuthentication generates PublicKeyCredentialRequestOptions for the
	// user identified by userID. Pass a nil or empty userID to request a
	// discoverable-credential (passkey) flow where the client will present
	// any registered credential.
	//
	// The implementation is responsible for issuing a challenge with
	// sufficient entropy and for associating it with the session so it can
	// be verified in FinishAuthentication.
	BeginAuthentication(ctx context.Context, userID []byte) (*PublicKeyCredentialRequestOptions, error)

	// FinishAuthentication verifies the AuthenticatorAssertionResponse:
	//   1. Validates the challenge against the one issued in BeginAuthentication.
	//   2. Looks up the stored public key for resp.CredentialID.
	//   3. Verifies resp.Signature over resp.AuthenticatorData + hash(resp.ClientDataJSON).
	//   4. Checks resp.AuthenticatorData.signCount > stored counter (replay prevention).
	//   5. Updates the stored sign counter on success.
	//
	// On success it returns the principal (e.g. a user record, claims map, or
	// opaque user handle) associated with the credential.
	FinishAuthentication(ctx context.Context, resp *AuthenticatorAssertionResponse) (principal interface{}, err error)
}

// --- WebAuthnScheme ---

// WebAuthnScheme implements SecurityScheme using the WebAuthn / FIDO2
// authentication ceremony. It delegates credential storage and challenge
// state management to the caller-supplied WebAuthnAuthenticator, consistent
// with how BearerScheme delegates token validation to a BearerValidateFunc.
//
// The Authenticate method reads an AuthenticatorAssertionResponse from the
// request body (expected as individual parsed fields attached to the request
// context by the caller's handler) and forwards it to
// WebAuthnAuthenticator.FinishAuthentication.
//
// Typical usage:
//
//	scheme := security.NewWebAuthnScheme("webauthn",
//	    myRegistrar,   // implements WebAuthnRegistrar
//	    myAuthenticator, // implements WebAuthnAuthenticator
//	)
//	secExt.Register(scheme)
//
// Registration endpoints (begin/finish) must be implemented by the application
// and are outside the scope of this scheme. Call scheme.Registrar() to access
// the WebAuthnRegistrar from route handlers.
type WebAuthnScheme struct {
	name          string
	description   string
	registrar     WebAuthnRegistrar
	authenticator WebAuthnAuthenticator
}

// assertionResponseKey is the context key used to pass an
// AuthenticatorAssertionResponse through the request context to Authenticate.
type assertionResponseKey struct{}

// NewWebAuthnScheme creates a WebAuthn authentication scheme.
//
// name is the unique scheme identifier (e.g. "webauthn" or "passkey").
// registrar handles the registration ceremony (may be nil if registration
// is managed outside this extension).
// authenticator handles the authentication ceremony and must not be nil.
func NewWebAuthnScheme(name string, registrar WebAuthnRegistrar, authenticator WebAuthnAuthenticator) *WebAuthnScheme {
	if name == "" {
		name = "webauthn"
	}
	if authenticator == nil {
		panic("security.NewWebAuthnScheme: authenticator must not be nil")
	}
	return &WebAuthnScheme{
		name:          name,
		description:   "WebAuthn / FIDO2 public-key authentication",
		registrar:     registrar,
		authenticator: authenticator,
	}
}

// Name returns the unique scheme identifier.
func (s *WebAuthnScheme) Name() string { return s.name }

// Type returns the OpenAPI security scheme type. WebAuthn does not map to a
// standard OpenAPI scheme; "http" with a custom description is the closest
// approximation.
func (s *WebAuthnScheme) Type() string { return "http" }

// Description returns the human-readable scheme description.
func (s *WebAuthnScheme) Description() string { return s.description }

// SetDescription overrides the default description for OpenAPI documentation.
func (s *WebAuthnScheme) SetDescription(desc string) *WebAuthnScheme {
	s.description = desc
	return s
}

// Registrar returns the WebAuthnRegistrar supplied at construction time.
// Use this from registration route handlers to call BeginRegistration and
// FinishRegistration.
func (s *WebAuthnScheme) Registrar() WebAuthnRegistrar { return s.registrar }

// Authenticator returns the WebAuthnAuthenticator supplied at construction time.
func (s *WebAuthnScheme) Authenticator() WebAuthnAuthenticator { return s.authenticator }

// WithAssertionResponse returns a new context carrying the assertion response.
// Call this in the route handler before the middleware invokes Authenticate,
// or pass the context to a manual Authenticate call:
//
//	ctx := security.WithAssertionResponse(r.Context(), assertionResp)
//	principal, err := scheme.Authenticate(r.WithContext(ctx))
func WithAssertionResponse(ctx context.Context, resp *AuthenticatorAssertionResponse) context.Context {
	return context.WithValue(ctx, assertionResponseKey{}, resp)
}

// Authenticate implements SecurityScheme. It reads the
// AuthenticatorAssertionResponse from the request context (set via
// WithAssertionResponse) and delegates to WebAuthnAuthenticator.FinishAuthentication.
//
// If no assertion response is present in the context an error is returned,
// signalling that the route handler must place the parsed response in the
// context before the scheme middleware executes (or before a manual call).
func (s *WebAuthnScheme) Authenticate(r *http.Request) (interface{}, error) {
	resp, ok := r.Context().Value(assertionResponseKey{}).(*AuthenticatorAssertionResponse)
	if !ok || resp == nil {
		return nil, fmt.Errorf("webauthn: no AuthenticatorAssertionResponse in request context — use security.WithAssertionResponse")
	}
	return s.authenticator.FinishAuthentication(r.Context(), resp)
}

// Challenge returns the WWW-Authenticate challenge header value.
// WebAuthn does not define a standard challenge header; an empty string is
// returned so that the middleware omits the WWW-Authenticate header and the
// application can redirect to its own WebAuthn assertion initiation endpoint.
func (s *WebAuthnScheme) Challenge() string { return "" }

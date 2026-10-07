// Package authclient validates bearer tokens issued by AuthService, and provides
// net/http middleware for any service that sits behind it — an API, an MCP server,
// or any other OAuth 2.1 / OIDC resource server. Nothing here talks to the auth
// service except to fetch and cache its JWKS; every request is verified locally.
package authclient

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenValidationError is returned by Validate when a token is malformed, expired,
// or fails signature/issuer/audience verification.
type TokenValidationError struct {
	msg string
}

func (e *TokenValidationError) Error() string { return e.msg }

func validationErrorf(format string, args ...any) error {
	return &TokenValidationError{msg: fmt.Sprintf(format, args...)}
}

type jsonWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jsonWebKey `json:"keys"`
}

// TokenValidator fetches and caches the auth service's JWKS, and verifies bearer
// tokens locally. No network call to the auth service happens per request — only
// when the JWKS cache is cold or a token references an unknown kid (e.g. right
// after key rotation).
type TokenValidator struct {
	Issuer     string
	ResourceID string

	jwksURL    string
	cacheTTL   time.Duration
	httpClient *http.Client

	mu          sync.Mutex
	jwks        jwksDocument
	cacheExpiry time.Time
}

// Option configures a TokenValidator constructed with New.
type Option func(*TokenValidator)

// WithJWKSURL overrides the default "{issuer}/jwks.json" JWKS endpoint.
func WithJWKSURL(url string) Option {
	return func(v *TokenValidator) { v.jwksURL = url }
}

// WithCacheTTL overrides the default 5 minute JWKS cache lifetime.
func WithCacheTTL(ttl time.Duration) Option {
	return func(v *TokenValidator) { v.cacheTTL = ttl }
}

// WithHTTPClient overrides the default HTTP client used to fetch the JWKS.
func WithHTTPClient(client *http.Client) Option {
	return func(v *TokenValidator) { v.httpClient = client }
}

// New builds a TokenValidator for the given issuer and resource ID (the `aud`
// value tokens must carry — typically the URL of your API).
func New(issuer, resourceID string, opts ...Option) *TokenValidator {
	v := &TokenValidator{
		Issuer:     issuer,
		ResourceID: resourceID,
		jwksURL:    strings.TrimRight(issuer, "/") + "/jwks.json",
		cacheTTL:   5 * time.Minute,
		httpClient: &http.Client{Timeout: 3 * time.Second},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate verifies a bearer token's signature, exp, iss, and aud (must equal
// ResourceID). It returns the decoded claims on success, or a *TokenValidationError
// on failure.
func (v *TokenValidator) Validate(tokenString string) (jwt.MapClaims, error) {
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, validationErrorf("malformed token")
	}

	kid, _ := unverified.Header["kid"].(string)
	if kid == "" {
		return nil, validationErrorf("unknown signing key")
	}

	key, err := v.findKey(kid)
	if err != nil {
		return nil, validationErrorf("%s", err)
	}
	if key == nil {
		return nil, validationErrorf("unknown signing key")
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
		return key, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.ResourceID),
	)
	if err != nil || !parsed.Valid {
		return nil, validationErrorf("%s", err)
	}
	return claims, nil
}

// HasScope reports whether claims carries the given scope in its space-separated
// `scope` claim.
func HasScope(claims jwt.MapClaims, scope string) bool {
	raw, _ := claims["scope"].(string)
	for _, s := range strings.Fields(raw) {
		if s == scope {
			return true
		}
	}
	return false
}

func (v *TokenValidator) findKey(kid string) (*rsa.PublicKey, error) {
	doc, err := v.getJWKS(false)
	if err != nil {
		return nil, err
	}
	if key := lookupKey(doc, kid); key != nil {
		return jwkToRSAPublicKey(key)
	}

	doc, err = v.getJWKS(true)
	if err != nil {
		return nil, err
	}
	if key := lookupKey(doc, kid); key != nil {
		return jwkToRSAPublicKey(key)
	}
	return nil, nil
}

func lookupKey(doc jwksDocument, kid string) *jsonWebKey {
	for i := range doc.Keys {
		if doc.Keys[i].Kid == kid {
			return &doc.Keys[i]
		}
	}
	return nil
}

func (v *TokenValidator) getJWKS(forceRefresh bool) (jwksDocument, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !forceRefresh && time.Now().Before(v.cacheExpiry) {
		return v.jwks, nil
	}

	resp, err := v.httpClient.Get(v.jwksURL)
	if err != nil {
		return jwksDocument{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return jwksDocument{}, fmt.Errorf("jwks fetch failed: %s", resp.Status)
	}

	var doc jwksDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return jwksDocument{}, err
	}

	v.jwks = doc
	v.cacheExpiry = time.Now().Add(v.cacheTTL)
	return v.jwks, nil
}

func jwkToRSAPublicKey(key *jsonWebKey) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", key.Kty)
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("invalid jwk exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

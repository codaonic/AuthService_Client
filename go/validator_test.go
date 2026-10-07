package authclient

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer     = "https://auth.example.com"
	testResourceID = "https://api.example.com"
	testKid        = "test-key-1"
)

type testKeypair struct {
	private *rsa.PrivateKey
	jwks    jwksDocument
}

func newTestKeypair(t *testing.T) *testKeypair {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := jsonWebKey{
		Kid: testKid,
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(private.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(private.PublicKey.E)).Bytes()),
	}
	return &testKeypair{private: private, jwks: jwksDocument{Keys: []jsonWebKey{jwk}}}
}

type tokenOpts struct {
	aud   string
	iss   string
	scope string
	sub   string
	ttl   time.Duration
}

func (kp *testKeypair) makeToken(t *testing.T, opts tokenOpts) string {
	t.Helper()
	if opts.aud == "" {
		opts.aud = testResourceID
	}
	if opts.iss == "" {
		opts.iss = testIssuer
	}
	if opts.scope == "" {
		opts.scope = "profile email"
	}
	if opts.sub == "" {
		opts.sub = "user-123"
	}
	if opts.ttl == 0 {
		opts.ttl = 10 * time.Minute
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   opts.sub,
		"aud":   opts.aud,
		"iss":   opts.iss,
		"scope": opts.scope,
		"iat":   now.Unix(),
		"exp":   now.Add(opts.ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKid
	signed, err := token.SignedString(kp.private)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func newJWKSServer(t *testing.T, kp *testKeypair) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(kp.jwks)
	}))
	t.Cleanup(server.Close)
	return server
}

func newValidator(t *testing.T, kp *testKeypair) *TokenValidator {
	server := newJWKSServer(t, kp)
	return New(testIssuer, testResourceID, WithJWKSURL(server.URL))
}

func TestValidTokenReturnsClaims(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{sub: "user-123"})

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims["sub"] != "user-123" {
		t.Errorf("sub = %v, want user-123", claims["sub"])
	}
	if claims["aud"] != testResourceID {
		t.Errorf("aud = %v, want %v", claims["aud"], testResourceID)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{aud: "https://other.example.com"})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestWrongIssuerRejected(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{iss: "https://not-the-real-as.example.com"})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{ttl: -time.Minute})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestUnknownKidRejected(t *testing.T) {
	kp := newTestKeypair(t)
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDocument{Keys: []jsonWebKey{}})
	}))
	defer empty.Close()

	v := New(testIssuer, testResourceID, WithJWKSURL(empty.URL))
	token := kp.makeToken(t, tokenOpts{})

	if _, err := v.Validate(token); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestHasScope(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	token := kp.makeToken(t, tokenOpts{scope: "profile email"})

	claims, err := v.Validate(token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !HasScope(claims, "profile") {
		t.Error("expected profile scope")
	}
	if HasScope(claims, "admin") {
		t.Error("did not expect admin scope")
	}
}

func TestJWKSCachedAcrossCalls(t *testing.T) {
	kp := newTestKeypair(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(kp.jwks)
	}))
	defer server.Close()

	v := New(testIssuer, testResourceID, WithJWKSURL(server.URL))
	token := kp.makeToken(t, tokenOpts{})

	if _, err := v.Validate(token); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := v.Validate(token); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if calls != 1 {
		t.Errorf("jwks fetched %d times, want 1", calls)
	}
}

package authclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestMux(v *TokenValidator) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterProtectedResource(mux, testResourceID, testIssuer, "Example API")

	mux.Handle("/me", RequireAuth(v, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"` + claims["sub"].(string) + `"}`))
	})))

	mux.Handle("/profile", RequireScope(v, "profile")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"` + claims["sub"].(string) + `"}`))
	})))

	return mux
}

func TestMissingTokenReturns401WithChallenge(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	server := httptest.NewServer(newTestMux(v))
	defer server.Close()

	resp, err := http.Get(server.URL + "/me")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Errorf("WWW-Authenticate = %q, want resource_metadata", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestValidTokenAllowsAccess(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	server := httptest.NewServer(newTestMux(v))
	defer server.Close()

	token := kp.makeToken(t, tokenOpts{sub: "user-1"})
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMissingScopeReturns403(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	server := httptest.NewServer(newTestMux(v))
	defer server.Close()

	token := kp.makeToken(t, tokenOpts{scope: "email"})
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	kp := newTestKeypair(t)
	v := newValidator(t, kp)
	server := httptest.NewServer(newTestMux(v))
	defer server.Close()

	resp, err := http.Get(server.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

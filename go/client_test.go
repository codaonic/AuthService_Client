package authclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func logoutServer(t *testing.T, status int, body string, seen *url.Values) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/logout" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if seen != nil {
			*seen = r.PostForm
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func TestLogoutPostsClientCredentialsAndRefreshToken(t *testing.T) {
	var seen url.Values
	server := logoutServer(t, http.StatusOK, `{"status":"signed_out"}`, &seen)
	client := NewClient(server.URL+"/", "my-app", WithClientSecret("s3cret"))

	ok, err := client.Logout(context.Background(), "rt-123")
	if err != nil || !ok {
		t.Fatalf("Logout = %v, %v; want true, nil", ok, err)
	}
	if seen.Get("client_id") != "my-app" || seen.Get("client_secret") != "s3cret" || seen.Get("refresh_token") != "rt-123" {
		t.Errorf("unexpected form: %v", seen)
	}
}

func TestLogoutPublicClientSendsNoSecret(t *testing.T) {
	var seen url.Values
	server := logoutServer(t, http.StatusOK, `{}`, &seen)

	if _, err := NewClient(server.URL, "my-app").Logout(context.Background(), "rt-123"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, present := seen["client_secret"]; present {
		t.Errorf("client_secret should not be sent: %v", seen)
	}
}

func TestLogoutReturnsFalseWhenTokenIsNoLongerKnown(t *testing.T) {
	server := logoutServer(t, http.StatusBadRequest, `{"detail":"invalid_grant"}`, nil)

	ok, err := NewClient(server.URL, "my-app").Logout(context.Background(), "stale")
	if err != nil || ok {
		t.Fatalf("Logout = %v, %v; want false, nil", ok, err)
	}
}

func TestLogoutErrorsOnBadClientCredentials(t *testing.T) {
	server := logoutServer(t, http.StatusUnauthorized, `{"detail":"invalid_client"}`, nil)

	_, err := NewClient(server.URL, "my-app").Logout(context.Background(), "rt-123")
	var logoutErr *LogoutError
	if !errors.As(err, &logoutErr) {
		t.Fatalf("err = %v; want *LogoutError", err)
	}
}

func TestLogoutErrorsOnNetworkFailure(t *testing.T) {
	server := logoutServer(t, http.StatusOK, `{}`, nil)
	client := NewClient(server.URL, "my-app")
	server.Close()

	_, err := client.Logout(context.Background(), "rt-123")
	var logoutErr *LogoutError
	if !errors.As(err, &logoutErr) {
		t.Fatalf("err = %v; want *LogoutError", err)
	}
}

func TestLogoutURL(t *testing.T) {
	client := NewClient(testIssuer+"/", "my app")

	if got, want := client.LogoutURL("", ""), testIssuer+"/logout?client_id=my+app"; got != want {
		t.Errorf("LogoutURL = %q; want %q", got, want)
	}

	parsed, err := url.Parse(client.LogoutURL("https://app.example.com/signed-out?x=1", "abc"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != "my app" ||
		query.Get("post_logout_redirect_uri") != "https://app.example.com/signed-out?x=1" ||
		query.Get("state") != "abc" {
		t.Errorf("unexpected query: %v", query)
	}
}

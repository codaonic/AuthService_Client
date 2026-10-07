package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type claimsContextKey struct{}

// ClaimsFromContext returns the claims a RequireAuth/RequireScope middleware
// attached to the request context, if any.
func ClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(jwt.MapClaims)
	return claims, ok
}

func writeJSONError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func challengeHeader(r *http.Request, errCode string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	resourceMetadataURL := scheme + "://" + r.Host + "/.well-known/oauth-protected-resource"
	challenge := `Bearer resource_metadata="` + resourceMetadataURL + `"`
	if errCode != "" {
		challenge += `, error="` + errCode + `"`
	}
	return challenge
}

// RequireAuth wraps next with bearer-token validation. A request with no or
// invalid token gets a 401 with a WWW-Authenticate header pointing at this
// resource's /.well-known/oauth-protected-resource — the same 401-then-discover
// pattern an MCP client expects. On success, the verified claims are attached to
// the request context (read them back with ClaimsFromContext).
func RequireAuth(validator *TokenValidator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			w.Header().Set("WWW-Authenticate", challengeHeader(r, ""))
			writeJSONError(w, http.StatusUnauthorized, "missing_bearer_token")
			return
		}

		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		claims, err := validator.Validate(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", challengeHeader(r, "invalid_token"))
			writeJSONError(w, http.StatusUnauthorized, err.Error())
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireScope is RequireAuth plus a check that the token's claims carry every
// one of the given scopes; otherwise it responds 403.
func RequireScope(validator *TokenValidator, scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return RequireAuth(validator, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _ := ClaimsFromContext(r.Context())
			var missing []string
			for _, scope := range scopes {
				if !HasScope(claims, scope) {
					missing = append(missing, scope)
				}
			}
			if len(missing) > 0 {
				writeJSONError(w, http.StatusForbidden, "missing_scope: "+strings.Join(missing, ", "))
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

package authclient

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourceHandler serves RFC 9728 Protected Resource Metadata at
// /.well-known/oauth-protected-resource, served BY this resource server,
// pointing back at the auth service. MCP clients fetch this after a 401 to
// discover which authorization server to use.
func ProtectedResourceHandler(resourceID, authorizationServer, resourceName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"resource":                 resourceID,
			"authorization_servers":    []string{authorizationServer},
			"bearer_methods_supported": []string{"header"},
		}
		if resourceName != "" {
			body["resource_name"] = resourceName
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
}

// RegisterProtectedResource registers ProtectedResourceHandler on mux at the
// well-known path.
func RegisterProtectedResource(mux *http.ServeMux, resourceID, authorizationServer, resourceName string) {
	mux.Handle("/.well-known/oauth-protected-resource", ProtectedResourceHandler(resourceID, authorizationServer, resourceName))
}

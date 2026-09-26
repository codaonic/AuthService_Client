# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-27

### Added

- `TokenValidator` — verifies a bearer token's signature, `exp`, `iss`, and `aud` against a cached JWKS, with no per-request network call to the auth service.
- `authservice_client.fastapi.make_auth_dependency` / `make_scope_dependency` — FastAPI dependencies for requiring a valid token, optionally with specific scopes.
- `authservice_client.protected_resource.protected_resource_router` — serves RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`), enabling the 401-then-discover flow MCP clients expect.
- Initial extraction from the main AuthService monorepo into its own installable, versioned package.

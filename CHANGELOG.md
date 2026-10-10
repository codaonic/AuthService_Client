# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Renamed the project from `authservice-client` to `auth-client` (Python distribution name, Python module `auth_client`, repo name).

### Added

- Go client (`go/`, module `github.com/codaonic/auth-client/go`): `TokenValidator`, `net/http` middleware (`RequireAuth`, `RequireScope`), and a protected-resource-metadata handler, at feature parity with the Python client.
- Node / TypeScript client (`node/`, package `auth-client`): `TokenValidator` (built on `jose`), Express middleware (`makeAuthMiddleware`, `makeScopeMiddleware`), and `protectedResourceRouter`, at feature parity with the Python client.
- Logout for applications that sign users in, at parity across all three clients: Python `AuthServiceClient` (`logout`, async `alogout`, `logout_url`) with `LogoutError`; Go `Client` via `NewClient` (`Logout`, `LogoutURL`) with `*LogoutError`; Node `AuthServiceClient` (`logout`, `logoutUrl`) with `LogoutError`. Each signs a user out of the calling application only, via AuthService's `POST /logout`, or builds the browser-redirect URL.
- README: "Sign-in timeout and logout" — how services behind AuthService handle the per-application sign-in timeout and log users out, with Python, Go, and Node examples.

## [0.1.0] - 2026-09-27

### Added

- `TokenValidator` — verifies a bearer token's signature, `exp`, `iss`, and `aud` against a cached JWKS, with no per-request network call to the auth service.
- `auth_client.fastapi.make_auth_dependency` / `make_scope_dependency` — FastAPI dependencies for requiring a valid token, optionally with specific scopes.
- `auth_client.protected_resource.protected_resource_router` — serves RFC 9728 Protected Resource Metadata (`/.well-known/oauth-protected-resource`), enabling the 401-then-discover flow MCP clients expect.
- Initial extraction from the main AuthService monorepo into its own installable, versioned package.

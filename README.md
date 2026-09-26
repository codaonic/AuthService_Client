# authservice-client

![version](https://img.shields.io/badge/version-0.1.0-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Token validation and FastAPI integration helpers for any service that sits behind
[AuthService](https://github.com/codaonic/AuthService) — a website's API, an MCP
server, or any other OAuth 2.1 / OIDC resource server. Nothing here talks to the
auth service except to fetch and cache its JWKS; every request is verified locally.

Not published to PyPI — install it directly from this repo (see below).

## Contents

- [Install](#install)
- [Framework-agnostic validation](#framework-agnostic-validation)
- [FastAPI](#fastapi)
- [Custom middleware with your own authorization logic](#custom-middleware-with-your-own-authorization-logic)
- [Other languages](#other-languages)
- [Registering your service](#registering-your-service)
- [Local development](#local-development)
- [Versioning](#versioning)
- [License](#license)

## Install

This isn't on PyPI, so install it straight from GitHub. Pin a tag (e.g. `@v0.1.0`)
for anything beyond local experimentation — `main` can move.

```bash
# uv
uv add "authservice-client @ git+https://github.com/codaonic/AuthService_Client.git@main"
# with the FastAPI helpers:
uv add "authservice-client[fastapi] @ git+https://github.com/codaonic/AuthService_Client.git@main"

# pip
pip install "authservice-client[fastapi] @ git+https://github.com/codaonic/AuthService_Client.git@main"

# poetry
poetry add "git+https://github.com/codaonic/AuthService_Client.git#main"
```

Pinned to a release tag instead of a branch:

```bash
uv add "authservice-client @ git+https://github.com/codaonic/AuthService_Client.git@v0.1.0"
```

If this repo is private for you, use the SSH form instead — whoever installs it
needs GitHub access already set up (SSH key or a credential helper):

```bash
uv add "authservice-client @ git+ssh://git@github.com/codaonic/AuthService_Client.git@main"
```

## Framework-agnostic validation

```python
from authservice_client import TokenValidator, TokenValidationError

validator = TokenValidator(
    issuer="https://auth.yourdomain.com",
    resource_id="https://api.yourdomain.com",  # must match the `resource=` this token was issued for
)

try:
    claims = validator.validate(token)  # verifies signature, exp, iss, aud
except TokenValidationError:
    ...  # reject the request
```

## FastAPI

```python
from fastapi import Depends, FastAPI

from authservice_client import TokenValidator
from authservice_client.fastapi import make_auth_dependency, make_scope_dependency
from authservice_client.protected_resource import protected_resource_router

ISSUER = "https://auth.yourdomain.com"
RESOURCE_ID = "https://api.yourdomain.com"

validator = TokenValidator(issuer=ISSUER, resource_id=RESOURCE_ID)
require_auth = make_auth_dependency(validator)
require_profile_scope = make_scope_dependency(validator, "profile")

app = FastAPI()

# RFC 9728 metadata, served BY this resource server, pointing back at the auth service.
# MCP clients fetch this after a 401 to discover which authorization server to use.
app.include_router(protected_resource_router(RESOURCE_ID, ISSUER, resource_name="Your API"))


@app.get("/me")
async def me(claims: dict = Depends(require_auth)):
    return {"sub": claims["sub"]}


@app.get("/profile")
async def profile(claims: dict = Depends(require_profile_scope)):
    return {"sub": claims["sub"]}
```

A request with no/invalid token gets a `401` with a
`WWW-Authenticate: Bearer resource_metadata="…"` header pointing at your
`/.well-known/oauth-protected-resource` — the same 401-then-discover pattern an
MCP client expects.

## Custom middleware with your own authorization logic

`make_auth_dependency` / `make_scope_dependency` cover the common case, but
`TokenValidator` is plain Python — nothing stops you from calling it yourself
from an ASGI middleware and layering on whatever authorization rules your
service needs (roles, tenant checks, per-route policy, etc.) instead of, or
alongside, scopes:

```python
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from authservice_client import TokenValidator, TokenValidationError

validator = TokenValidator(issuer=ISSUER, resource_id=RESOURCE_ID)


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return JSONResponse({"detail": "missing_bearer_token"}, status_code=401)

        try:
            claims = validator.validate(header.removeprefix("Bearer ").strip())
        except TokenValidationError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=401)

        # your own authorization logic goes here, e.g. role- or tenant-based checks
        if request.url.path.startswith("/admin") and claims.get("role") != "admin":
            return JSONResponse({"detail": "forbidden"}, status_code=403)

        request.state.claims = claims
        return await call_next(request)


app = FastAPI()
app.add_middleware(AuthMiddleware)


@app.get("/me")
async def me(request: Request):
    return {"sub": request.state.claims["sub"]}
```

This works the same way outside FastAPI too — any ASGI/WSGI middleware, or a
plain decorator, can call `validator.validate(token)` and apply its own checks
against the returned claims dict.

## Other languages

There's no SDK here for non-Python services, but the pattern is a handful of
lines in any language with an HTTP client and a JWT library:

1. `GET {issuer}/jwks.json` once, cache it (refresh on a cache-miss `kid`, e.g. every 5–10 min).
2. Verify the token's signature, `exp`, `iss` (must equal `{issuer}`), and `aud` (must equal your `resource_id`).
3. Read `sub` / `scope` off the verified claims.

Equivalent libraries: `jose` or `jsonwebtoken` + `jwks-rsa` in Node,
`github.com/coreos/go-oidc` in Go, `jose4j` in Java.

## Registering your service

Before any of this works, the auth service needs to know about your resource
and your client — either via its `/admin` UI or its CLI, from the AuthService
repo itself:

```bash
uv run python -m app.cli register-resource --resource-id "https://api.yourdomain.com" --name "Your API"
uv run python -m app.cli register-client --client-id your-app --type public --redirect-uri "https://yourdomain.com/callback"
```

Or, for a client that registers itself at runtime (e.g. an MCP client), use
Dynamic Client Registration: `POST {issuer}/register`.

See the [AuthService repo](https://github.com/codaonic/AuthService) for the
auth server itself, its admin UI, and complete runnable example resource
servers built on this SDK.

## Local development

```bash
git clone https://github.com/codaonic/AuthService_Client.git
cd AuthService_Client
uv sync
uv run pytest
```

The test suite is fully self-contained (mocked JWKS via `httpx.MockTransport`)
— it never talks to a real auth service.

## Versioning

This project follows [Semantic Versioning](https://semver.org/). See
[CHANGELOG.md](CHANGELOG.md) for release notes, and use a tag (`@vX.Y.Z`) in
your install command to pin a specific version.

## License

MIT — see [LICENSE](LICENSE).

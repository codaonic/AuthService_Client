from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from auth_client import AuthServiceClient, LogoutError
from tests.helpers import ISSUER


def _transport(status: int, body: dict, seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def _client(status=200, body=None, seen=None, secret="s3cret"):
    transport = _transport(status, body if body is not None else {"status": "signed_out"}, seen if seen is not None else [])
    return AuthServiceClient(
        ISSUER,
        "my-app",
        client_secret=secret,
        http_client=httpx.Client(transport=transport),
        async_http_client=httpx.AsyncClient(transport=transport),
    )


def test_logout_posts_client_credentials_and_refresh_token():
    seen: list = []
    assert _client(seen=seen).logout("rt-123") is True

    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == f"{ISSUER}/logout"
    form = parse_qs(request.content.decode())
    assert form == {"client_id": ["my-app"], "client_secret": ["s3cret"], "refresh_token": ["rt-123"]}


def test_public_client_sends_no_secret():
    seen: list = []
    _client(seen=seen, secret=None).logout("rt-123")
    assert "client_secret" not in parse_qs(seen[0].content.decode())


def test_logout_returns_false_when_token_is_no_longer_known():
    assert _client(status=400, body={"detail": "invalid_grant"}).logout("stale") is False


def test_logout_raises_on_bad_client_credentials():
    with pytest.raises(LogoutError):
        _client(status=401, body={"detail": "invalid_client"}).logout("rt-123")


def test_logout_raises_on_network_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = AuthServiceClient(ISSUER, "my-app", http_client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(LogoutError):
        client.logout("rt-123")


async def test_alogout_behaves_like_logout():
    seen: list = []
    assert await _client(seen=seen).alogout("rt-123") is True
    assert parse_qs(seen[0].content.decode())["refresh_token"] == ["rt-123"]
    assert await _client(status=400, body={"detail": "invalid_grant"}).alogout("stale") is False


def test_logout_url():
    client = AuthServiceClient(f"{ISSUER}/", "my app")
    assert client.logout_url() == f"{ISSUER}/logout?client_id=my+app"

    url = urlparse(client.logout_url("https://app.example.com/signed-out?x=1", state="abc"))
    assert parse_qs(url.query) == {
        "client_id": ["my app"],
        "post_logout_redirect_uri": ["https://app.example.com/signed-out?x=1"],
        "state": ["abc"],
    }

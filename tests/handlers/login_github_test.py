"""Tests for the /login route with GitHub."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.providers.github import GitHubProvider
from tests.setup import SetupTest
from tests.support.app import store_secret

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_login(tmp_path: Path, aiohttp_client: TestClient) -> None:
    secret_path = store_secret(tmp_path, "github", b"some-client-secret")
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET_FILE": str(secret_path),
    }
    setup = await SetupTest.create(tmp_path, **config)
    client = await aiohttp_client(setup.app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        params={"rd": "https://example.com/foo?a=bar&b=baz"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert "github.com" in url.netloc
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "client_id": ["some-client-id"],
        "scope": [" ".join(GitHubProvider._SCOPES)],
        "state": [ANY],
    }

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"

    # Check that the /auth route works and finds our token.
    r = await client.get("/auth", params={"capability": "read:all"})
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "read:all"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Uid"] == "123456"
    expected = "org-a-team,org-other-team,other-org-team-with-very--F279yg"
    assert r.headers["X-Auth-Request-Groups"] == expected
    assert r.headers["X-Auth-Request-Token"]

    # Now ask for the ticket in the encrypted session to be analyzed, and
    # verify the internals of the ticket from GitHub authentication.
    r = await client.get("/auth/analyze")
    assert r.status == 200
    data = await r.json()
    assert data == {
        "handle": {"key": ANY, "secret": ANY},
        "session": {
            "email": "githubuser@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {"alg": ALGORITHM, "typ": "JWT", "kid": "some-kid"},
            "data": {
                "aud": setup.config.issuer.aud,
                "email": "githubuser@example.com",
                "exp": ANY,
                "iat": ANY,
                "isMemberOf": [
                    {"name": "org-a-team", "id": 1000},
                    {"name": "org-other-team", "id": 1001},
                    {"name": "other-org-team-with-very--F279yg", "id": 1002},
                ],
                "iss": setup.config.issuer.iss,
                "jti": ANY,
                "name": "GitHub User",
                "scope": "read:all",
                "sub": "githubuser",
                "uid": "githubuser",
                "uidNumber": "123456",
            },
            "valid": True,
        },
    }


async def test_login_redirect_header(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    secret_path = store_secret(tmp_path, "github", b"some-client-secret")
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET_FILE": str(secret_path),
    }
    setup = await SetupTest.create(tmp_path, **config)
    client = await aiohttp_client(setup.app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        headers={
            "X-Auth-Request-Redirect": "https://example.com/foo?a=bar&b=baz"
        },
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"


async def test_login_no_destination(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    secret_path = store_secret(tmp_path, "github", b"some-client-secret")
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET_FILE": str(secret_path),
    }
    setup = await SetupTest.create(tmp_path, **config)
    client = await aiohttp_client(setup.app)

    # Simulate the initial authentication request.
    r = await client.get("/login", allow_redirects=False)
    assert r.status == 400


async def test_cookie_auth_with_token(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    """Test that cookie auth takes precedence over an Authorization header.

    JupyterHub sends an Authorization header in its internal requests with
    type token.  We want to ensure that we prefer our session cookie, rather
    than try to unsuccessfully parse that header.  Test this by completing a
    login to get a valid session and then make a request with a bogus
    Authorization header.
    """
    secret_path = store_secret(tmp_path, "github", b"some-client-secret")
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET_FILE": str(secret_path),
    }
    setup = await SetupTest.create(tmp_path, **config)
    client = await aiohttp_client(setup.app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        headers={
            "X-Auth-Request-Redirect": "https://example.com/foo?a=bar&b=baz"
        },
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"

    # Now make a request to the /auth endpoint with a bogus token.
    r = await client.get("/auth", params={"capability": "read:all"})
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"
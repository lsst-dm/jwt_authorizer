"""Set up the test suite."""

from __future__ import annotations

from typing import TYPE_CHECKING

from tests.support.app import create_test_app
from tests.support.tokens import create_oidc_test_token, create_test_token

if TYPE_CHECKING:
    from aiohttp import web
    from aioredis import Redis
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory
    from jwt_authorizer.tokens import VerifiedToken
    from pathlib import Path
    from typing import Any, List, Optional


class SetupTest:
    """Utility class for test setup.

    This class wraps creating a test aiohttp application, creating a factory
    for building the JWT Authorizer components, and accessing configuration
    settings.
    """

    @classmethod
    async def create(cls, tmp_path: Path, **config: Any) -> SetupTest:
        """Start a configured test aiohttp application.

        Parameters
        ----------
        tmp_path : `pathlib.Path`
            Root of the test's temporary directory.
        **config : `typing.Any`
            Additional configuration settings to pass to Dynaconf.
        """
        app = await create_test_app(tmp_path, **config)
        return cls(app)

    def __init__(self, app: web.Application) -> None:
        self.app = app
        self.config: Config = self.app["jwt_authorizer/config"]
        self.factory: ComponentFactory = self.app["jwt_authorizer/factory"]
        self.redis: Redis = self.app["jwt_authorizer/redis"]

    def create_token(
        self, *, groups: Optional[List[str]] = None, **claims: str
    ) -> VerifiedToken:
        """Create a signed internal token.

        Parameters
        ----------
        groups : List[`str`], optional
            Group memberships the generated token should have.
        **claims : `str`, optional
            Other attributes to set or override in the token.

        Returns
        -------
        token : `jwt_authorizer.tokens.VerifiedToken`
            The generated token.
        """
        return create_test_token(self.config, groups=groups, **claims)

    def create_oidc_token(
        self, *, groups: Optional[List[str]] = None, **claims: str
    ) -> VerifiedToken:
        """Create a signed OpenID Connect token.

        Parameters
        ----------
        groups : List[`str`], optional
            Group memberships the generated token should have.
        **claims : `str`, optional
            Other attributes to set or override in the token.

        Returns
        -------
        token : `jwt_authorizer.tokens.VerifiedToken`
            The generated token.
        """
        return create_oidc_test_token(self.config, groups=groups, **claims)
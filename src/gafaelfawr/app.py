"""Application setup for Gafaelfawr."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import aiohttp_csrf
import aiohttp_jinja2
import aiohttp_remotes
import aiohttp_session
import aioredis
import jinja2
from aiohttp.web import Application
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from cachetools import TTLCache
from dynaconf import LazySettings, Validator
from safir.http import init_http_session
from safir.logging import configure_logging
from safir.metadata import setup_metadata
from safir.middleware import bind_logger
from structlog import get_logger

from gafaelfawr.config import Config, Configuration
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.handlers import init_routes

if TYPE_CHECKING:
    from aiohttp import ClientSession
    from aioredis import Redis
    from typing import Optional

__all__ = ["create_app"]


async def create_app(
    settings_path: Optional[str] = None,
    redis_pool: Optional[Redis] = None,
    http_session: Optional[ClientSession] = None,
    **extra: str,
) -> Application:
    """Create and configure the Gafaelfawr application.

    Parameters
    ----------
    settings_path : `str`, optional
        Additional settings file to load.
    redis_pool : `aioredis.Redis`, optional
        Redis connection pool.  One will be constructed from the URL in the
        application settings if this is not provided.
    http_session : `aiohttp.ClientSession`, optional
        Client session to use if provided.  If one is not provided, it will be
        created dynamically by safir.  The provided session is not closed on
        app shutdown.
    **extra : `str`
        Additional configuration settings for Dynaconf.

    Returns
    -------
    application: `aiohttp.web.Application`
        The constructed application.
    """
    defaults_file = os.path.join(os.path.dirname(__file__), "defaults.yaml")
    if settings_path:
        settings_files = f"{defaults_file},{settings_path}"
    else:
        settings_files = defaults_file
    settings = LazySettings(SETTINGS_FILE_FOR_DYNACONF=settings_files, **extra)
    settings.validators.register(
        Validator("NO_VERIFY", "NO_AUTHORIZE", is_type_of=bool),
        Validator("GROUP_MAPPING", is_type_of=dict),
    )
    settings.validators.validate()
    config = Config.from_dynaconf(settings)

    configuration = Configuration()
    configure_logging(
        profile=configuration.profile,
        log_level=config.loglevel,
        name=configuration.logger_name,
    )

    logger = get_logger(configuration.logger_name)
    config.log_settings(logger)

    key_cache = TTLCache(maxsize=16, ttl=600)
    if not redis_pool:
        redis_pool = await aioredis.create_redis_pool(config.redis_url)
    factory = ComponentFactory(config, redis_pool, key_cache, http_session)

    app = Application()
    app["safir/config"] = configuration
    app["gafaelfawr/config"] = config
    app["gafaelfawr/factory"] = factory
    app["gafaelfawr/redis"] = redis_pool
    setup_metadata(package_name="gafaelfawr", app=app)
    await setup_middleware(app, config)
    app.on_cleanup.append(on_shutdown)
    app.add_routes(init_routes())

    if http_session:
        app["safir/http_session"] = http_session
    else:
        app.cleanup_ctx.append(init_http_session)

    return app


async def setup_middleware(app: Application, config: Config) -> None:
    """Add middleware to the application."""
    app.middlewares.append(bind_logger)

    # Unconditionally trust X-Forwarded-For, since this application is desiged
    # to run behind an nginx ingress.
    await aiohttp_remotes.setup(app, aiohttp_remotes.XForwardedRelaxed())

    # Set up encrypted session storage via a cookie.
    session_storage = EncryptedCookieStorage(
        config.session_secret, cookie_name="jwts"
    )
    aiohttp_session.setup(app, session_storage)

    # Configure global CSRF protection using session storage.
    csrf_policy = aiohttp_csrf.policy.FormPolicy("_csrf")
    csrf_storage = aiohttp_csrf.storage.SessionStorage("csrf")
    aiohttp_csrf.setup(app, policy=csrf_policy, storage=csrf_storage)

    templates_path = os.path.join(os.path.dirname(__file__), "templates")
    aiohttp_jinja2.setup(
        app, loader=jinja2.FileSystemLoader(templates_path),
    )


async def on_shutdown(app: Application) -> None:
    """Cleanly shut down the application."""
    redis_client = app["gafaelfawr/redis"]
    redis_client.close()
    await redis_client.wait_closed()


async def create_dev_app() -> Application:
    """Wrapper around create_app for development testing.

    Invoked by the ``run`` test environment to create a local server for
    testing.  Loads configuration from dev.yaml in the current directory.
    """
    config_path = os.path.join(os.getcwd(), "dev.yaml")
    return await create_app(config_path)
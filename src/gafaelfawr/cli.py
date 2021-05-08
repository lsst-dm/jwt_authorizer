"""Administrative command-line interface."""

from __future__ import annotations

import asyncio
import sys
from functools import wraps
from typing import TYPE_CHECKING

import click
import structlog
import uvicorn

from gafaelfawr.database import initialize_database
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.exceptions import KubernetesError
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.token import Token

if TYPE_CHECKING:
    from typing import Any, Awaitable, Callable, TypeVar, Union

    T = TypeVar("T")

__all__ = ["main", "generate_key", "help", "run"]


def coroutine(f: Callable[..., Awaitable[T]]) -> Callable[..., T]:
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        return asyncio.run(f(*args, **kwargs))

    return wrapper


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(message="%(version)s")
def main() -> None:
    """Gafaelfawr main.

    Administrative command-line interface for gafaelfawr.
    """
    pass


@main.command()
@click.argument("topic", default=None, required=False, nargs=1)
@click.pass_context
def help(ctx: click.Context, topic: Union[None, str]) -> None:
    """Show help for any command."""
    # The help command implementation is taken from
    # https://www.burgundywall.com/post/having-click-help-subcommand
    if topic:
        if topic in main.commands:
            click.echo(main.commands[topic].get_help(ctx))
        else:
            raise click.UsageError(f"Unknown help topic {topic}", ctx)
    else:
        assert ctx.parent
        click.echo(ctx.parent.get_help())


@main.command()
@click.option(
    "--port", default=8080, type=int, help="Port to run the application on."
)
def run(port: int) -> None:
    """Run the application (for testing only)."""
    uvicorn.run(
        "gafaelfawr.main:app", port=port, reload=True, reload_dirs=["src"]
    )


@main.command()
def generate_key() -> None:
    """Generate a new RSA key pair and print the private key."""
    keypair = RSAKeyPair.generate()
    print(keypair.private_key_as_pem())


@main.command()
def generate_token() -> None:
    """Generate an encoded token (such as the bootstrap token)."""
    print(str(Token()))


@main.command()
@click.option(
    "--settings",
    envvar="GAFAELFAWR_SETTINGS_PATH",
    type=str,
    default="/etc/gafaelfawr/gafaelfawr.yaml",
    help="Application settings file.",
)
def init(settings: str) -> None:
    """Initialize the database storage."""
    config_dependency.set_settings_path(settings)
    config = config_dependency()
    initialize_database(config)


@main.command()
@coroutine
async def update_service_tokens() -> None:
    """Update service tokens stored in Kubernetes secrets."""
    config = config_dependency()
    logger = structlog.get_logger(config.safir.logger_name)
    async with ComponentFactory.standalone() as factory:
        kubernetes_service = factory.create_kubernetes_service()
        try:
            await kubernetes_service.update_service_tokens()
        except KubernetesError as e:
            msg = "Failed to update service token secrets"
            logger.error(msg, error=str(e))
            sys.exit(1)

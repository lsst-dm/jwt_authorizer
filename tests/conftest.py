"""Test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from aioresponses import aioresponses

from tests.setup import SetupTest
from tests.support.app import create_test_app

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any, Awaitable, Callable, Iterable

    from aiohttp import web
    from aiohttp.pytest_plugin.test_utils import TestClient

    from tests.setup import SetupTestCallable


@pytest.fixture
def responses() -> Iterable[aioresponses]:
    """Create an aioresponses context manager.

    This can be used to mock responses to calls in an `aiohttp.ClientSession`.

    Returns
    -------
    mock : `aioresponses.aioresponses`
        The mock object with which URLs and callbacks can be registered.
    """
    with aioresponses(passthrough=["http://127.0.0.1"]) as mock:
        yield mock


@pytest.fixture
def create_test_setup(
    tmp_path: Path,
    responses: aioresponses,
    aiohttp_client: Callable[[web.Application], Awaitable[TestClient]],
) -> SetupTestCallable:
    """Create a test setup.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        Path to a per-test temporary directory, injected as a fixture.
    responses : `aioresponses.aioresponses`
        Mock object for `aiohttp.ClientSession` call handling.
    aiohttp_client : `typing.Callable`
        Function creates an aiohttp test client.

    Returns
    -------
    setup : `SetupTest`
        An object encapsulating the test setup.

    Notes
    -----
    This moderately complex fixture approach requires some explanation.

    The goal is to wrap test setup in an object, which can support various
    convenience methods for tests to create tokens, set up Redis state,
    configure the aiohttp client mock, or otherwise build an environment in
    which to do effective testing.  Among the things obviously required for
    that test setup is the test instance of the application and the test
    aiohttp client.

    However, creating the application is an async method, so it can't be a
    simple object constructor.  We also want to pass in a test environment to
    select between various test application configurations, and pytest
    fixtures cannot take an argument.  And, finally, we would like to hide the
    fact that the test setup depends on other fixtures so that every test
    doesn't have to repeat those fixtures.

    This fixture therefore constructs a function that, when called by the test
    with await, builds the test setup properly and returns it, hiding this
    complexity.
    """

    async def _create_test_setup(
        environment: str = "github", client: bool = True, **settings: Any,
    ) -> SetupTest:
        """Create a test setup for a given environment.

        Parameters
        ----------
        environment : `str`, optional
            The name of a configuration environment to use.
        client : `bool`, optional
            If set to `False`, do not start a test application or create a
            client.
        **settings : `typing.Any`
            Settings that override settings from the configuration file.

        Returns
        -------
        setup : `SetupTest`
            An object encapsulating the test setup.
        """
        app = await create_test_app(
            tmp_path, environment=environment, **settings
        )
        if client:
            client = await aiohttp_client(app)
            return SetupTest(app, responses, client)
        else:
            return SetupTest(app, responses)

    return _create_test_setup

"""Selenium tests for ``/auth/tokens``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.session import SessionHandle
from tests.pages.tokens import NewTokenPage, TokensPage
from tests.support.selenium import run

if TYPE_CHECKING:
    from seleniumwire import webdriver

    from tests.setup import SetupTestCallable


async def test_create_token(
    create_test_setup: SetupTestCallable, driver: webdriver.Chrome
) -> None:
    setup = await create_test_setup()
    token = setup.create_token(scope="read:all")
    driver.header_overrides = {"X-Auth-Request-Token": token.encoded}

    tokens_url = str(setup.client.make_url("/auth/tokens"))
    await run(lambda: driver.get(tokens_url))

    tokens_page = TokensPage(driver)
    assert tokens_page.tokens == []
    await tokens_page.click_create_token()

    new_tokens_page = NewTokenPage(driver)
    assert len(new_tokens_page.scopes) == 1
    scope = new_tokens_page.scopes[0]
    assert scope.label == "read:all"
    assert scope.description == "can read everything"
    assert not scope.checkbox.is_selected()
    scope.checkbox.click()
    await new_tokens_page.submit()

    tokens_page = TokensPage(driver)
    assert tokens_page.new_token
    session_handle = SessionHandle.from_str(tokens_page.new_token)
    assert len(tokens_page.tokens) == 1
    token_row = tokens_page.tokens[0]
    assert token_row.key == session_handle.key
    assert token_row.link.endswith(f"/auth/tokens/{session_handle.key}")
    assert token_row.scope == "read:all"
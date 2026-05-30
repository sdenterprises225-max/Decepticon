"""Tests for the web @tool wrappers (http_request event-loop safety)."""

from __future__ import annotations

import asyncio
import json

import pytest

from decepticon.tools.web import tools
from decepticon.tools.web.http import HTTPResponse


class _FakeSession:
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        tag: str = "",
    ) -> HTTPResponse:
        return HTTPResponse(
            id="resp-1",
            request_id="req-1",
            status=200,
            headers={"content-type": "text/plain"},
            body=b"pong",
            elapsed_ms=1.5,
            timestamp=2.0,
        )


@pytest.fixture
def patched_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tools, "_get_session", lambda: _FakeSession())


def test_http_request_returns_parsed_result_from_sync_context(patched_session: None) -> None:
    raw = tools.http_request.invoke({"method": "GET", "url": "https://target.test/ping"})
    parsed = json.loads(raw)
    assert "error" not in parsed
    assert parsed["status"] == 200
    assert parsed["body"] == "pong"


async def test_http_request_works_inside_running_event_loop(patched_session: None) -> None:
    loop = asyncio.get_running_loop()

    raw = await loop.run_in_executor(
        None,
        lambda: tools.http_request.invoke({"method": "GET", "url": "https://target.test/ping"}),
    )

    parsed = json.loads(raw)
    assert "error" not in parsed
    assert parsed["status"] == 200
    assert parsed["body"] == "pong"


async def test_run_coro_helper_works_with_active_running_loop() -> None:
    asyncio.get_running_loop()

    async def _coro() -> str:
        return "ok"

    assert tools._run_coro(_coro()) == "ok"

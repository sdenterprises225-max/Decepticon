from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from decepticon.skillogy.client.rest import (
    RestSkillogyClient,
    SkillogyClientError,
    _envelope_from_dict,
    _meta_from_dict,
)
from decepticon.skillogy.proto import (
    SkillEnvelope,
    SkillIngestResponse,
    SkillListResponse,
    SkillMeta,
)


def _make_client_with_transport(
    transport: httpx.MockTransport,
    base_url: str = "http://skillogy:9100",
    api_key: str | None = None,
    timeout: float = 10.0,
) -> RestSkillogyClient:
    c = RestSkillogyClient(base_url=base_url, api_key=api_key, timeout=timeout)
    real_async_client = httpx.AsyncClient

    def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    c._patcher = patch("httpx.AsyncClient", side_effect=patched)
    c._patcher.start()
    return c


def _stop(c: RestSkillogyClient) -> None:
    if hasattr(c, "_patcher"):
        c._patcher.stop()


class TestRestSkillogyClientInit:
    def test_defaults_base_timeout_headers_no_auth(self) -> None:
        c = RestSkillogyClient()
        assert c._base == "http://skillogy:9100"
        assert c._timeout == 10.0
        assert c._headers == {"Content-Type": "application/json"}
        assert "Authorization" not in c._headers

    def test_api_key_adds_bearer_header_and_rstrips_slash(self) -> None:
        c = RestSkillogyClient(base_url="http://h:9100/", api_key="secret", timeout=2.5)
        assert c._base == "http://h:9100"
        assert c._timeout == 2.5
        assert c._headers["Authorization"] == "Bearer secret"

    def test_empty_api_key_is_falsy_no_auth_header(self) -> None:
        c = RestSkillogyClient(api_key="")
        assert "Authorization" not in c._headers


class TestMetaFromDict:
    def test_full_dict_populates_all_fields(self) -> None:
        d = {
            "name": "n",
            "description": "d",
            "subdomain": "sub",
            "tags": ["a", "b"],
            "mitre_attack": ["T1190"],
            "path": "/p",
            "content_sha256": "abc",
            "size_bytes": "42",
            "safety_critical": True,
            "gated_by_conops": "c",
        }
        m = _meta_from_dict(d)
        assert m.name == "n"
        assert m.description == "d"
        assert m.subdomain == "sub"
        assert m.tags == ["a", "b"]
        assert m.mitre_attack == ["T1190"]
        assert m.path == "/p"
        assert m.content_sha256 == "abc"
        assert m.size_bytes == 42
        assert m.safety_critical is True
        assert m.gated_by_conops == "c"

    def test_empty_dict_returns_all_defaults(self) -> None:
        m = _meta_from_dict({})
        assert m.name == ""
        assert m.tags == []
        assert m.mitre_attack == []
        assert m.size_bytes == 0
        assert m.safety_critical is False
        assert m.gated_by_conops == ""

    def test_size_bytes_string_coerces_to_int(self) -> None:
        m = _meta_from_dict({"size_bytes": "99"})
        assert m.size_bytes == 99

    def test_none_values_use_or_defaults(self) -> None:
        m = _meta_from_dict({"name": None, "tags": None, "size_bytes": None})
        assert m.name == ""
        assert m.tags == []
        assert m.size_bytes == 0


class TestEnvelopeFromDict:
    def test_str_references_and_scripts_encoded_to_bytes(self) -> None:
        d = {
            "meta": {"name": "x"},
            "body": "b",
            "references": {"r.md": "text"},
            "scripts": {"s.sh": "echo"},
        }
        env = _envelope_from_dict(d)
        assert isinstance(env, SkillEnvelope)
        assert env.references["r.md"] == b"text"
        assert env.scripts["s.sh"] == b"echo"
        assert env.body == "b"
        assert env.meta.name == "x"

    def test_already_bytes_values_kept_as_bytes(self) -> None:
        d = {"references": {"r": b"raw"}}
        env = _envelope_from_dict(d)
        assert env.references["r"] == b"raw"
        assert env.body == ""
        assert env.scripts == {}
        assert env.meta == SkillMeta()

    def test_missing_keys_produce_empty_defaults(self) -> None:
        env = _envelope_from_dict({})
        assert env.body == ""
        assert env.references == {}
        assert env.scripts == {}


class TestPostJsonGetJsonImportError:
    async def test_post_json_raises_skillogy_client_error_when_httpx_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(__import__("sys").modules, "httpx", None)
        c = RestSkillogyClient()
        with pytest.raises(SkillogyClientError, match="httpx not installed"):
            await c._post_json("/x", {})

    async def test_get_json_raises_skillogy_client_error_when_httpx_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(__import__("sys").modules, "httpx", None)
        c = RestSkillogyClient()
        with pytest.raises(SkillogyClientError, match="httpx not installed"):
            await c._get_json("/x")


class TestHealthEndpoint:
    async def test_health_success_returns_dict(self) -> None:
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={"status": "ok", "skill_count": 3})

        c = _make_client_with_transport(httpx.MockTransport(handler), api_key="tok")
        try:
            result = await c.health()
        finally:
            _stop(c)
        assert result == {"status": "ok", "skill_count": 3}
        assert len(captured) == 1
        assert captured[0].method == "GET"
        assert captured[0].url.path == "/v1/health"
        assert captured[0].headers["Authorization"] == "Bearer tok"

    async def test_get_json_error_raises_skillogy_client_error_on_503(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text="oops")

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            with pytest.raises(SkillogyClientError, match="GET /v1/health returned HTTP 503"):
                await c.health()
        finally:
            _stop(c)

    async def test_get_json_error_message_includes_response_text(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="not found")

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            with pytest.raises(SkillogyClientError, match="not found"):
                await c.health()
        finally:
            _stop(c)


class TestPostJsonErrorBranch:
    async def test_post_json_error_raises_skillogy_client_error_on_400(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(400, text="bad request")

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            with pytest.raises(SkillogyClientError, match="POST /v1/skills:load returned HTTP 400"):
                await c.load_skill("/p")
        finally:
            _stop(c)


class TestListSkills:
    async def test_list_skills_single_page_returns_skills_and_resets_token(self) -> None:
        captured: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(json.loads(req.content))
            return httpx.Response(
                200,
                json={
                    "skills": [{"name": "a", "path": "/a"}, {"name": "b"}],
                    "total_count": 2,
                    "next_page_token": "",
                },
            )

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.list_skills(subdomain_filter=["x"])
        finally:
            _stop(c)
        assert isinstance(result, SkillListResponse)
        assert len(result.skills) == 2
        assert result.total_count == 2
        assert result.next_page_token == ""
        assert captured[0]["subdomain_filter"] == ["x"]
        assert captured[0]["page_token"] == ""
        assert captured[0]["page_size"] == 200

    async def test_list_skills_multi_page_pagination_accumulates_skills(self) -> None:
        call_count = 0

        def handler(req: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return httpx.Response(
                    200,
                    json={
                        "skills": [{"name": "a"}],
                        "total_count": 2,
                        "next_page_token": "tok1",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "skills": [{"name": "b"}],
                    "total_count": 2,
                    "next_page_token": "",
                },
            )

        captured_tokens: list[str] = []
        real_handler = handler

        def recording_handler(req: httpx.Request) -> httpx.Response:
            captured_tokens.append(json.loads(req.content).get("page_token", ""))
            return real_handler(req)

        c = _make_client_with_transport(httpx.MockTransport(recording_handler))
        try:
            result = await c.list_skills()
        finally:
            _stop(c)
        assert len(result.skills) == 2
        assert result.total_count == 2
        assert call_count == 2
        assert captured_tokens[0] == ""
        assert captured_tokens[1] == "tok1"

    async def test_list_skills_missing_keys_returns_empty_defaults(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.list_skills()
        finally:
            _stop(c)
        assert result.skills == []
        assert result.total_count == 0
        assert result.next_page_token == ""

    async def test_list_skills_passes_all_filter_kwargs_in_request_body(self) -> None:
        captured: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(json.loads(req.content))
            return httpx.Response(
                200,
                json={"skills": [], "total_count": 0, "next_page_token": ""},
            )

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            await c.list_skills(
                subdomain_filter=["s1"],
                tag_filter=["t1"],
                mitre_filter=["M1"],
                include_safety_critical=False,
                include_gated=False,
                page_size=50,
            )
        finally:
            _stop(c)
        body = captured[0]
        assert body["subdomain_filter"] == ["s1"]
        assert body["tag_filter"] == ["t1"]
        assert body["mitre_filter"] == ["M1"]
        assert body["include_safety_critical"] is False
        assert body["include_gated"] is False
        assert body["page_size"] == 50

    async def test_list_skills_none_filters_default_to_empty_lists(self) -> None:
        captured: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(json.loads(req.content))
            return httpx.Response(
                200,
                json={"skills": [], "total_count": 0, "next_page_token": ""},
            )

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            await c.list_skills()
        finally:
            _stop(c)
        assert captured[0]["subdomain_filter"] == []
        assert captured[0]["tag_filter"] == []
        assert captured[0]["mitre_filter"] == []


class TestLoadSkill:
    async def test_load_skill_success_returns_skill_envelope(self) -> None:
        captured: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(json.loads(req.content))
            return httpx.Response(
                200,
                json={
                    "skill": {
                        "meta": {"name": "t1", "subdomain": "s"},
                        "body": "# Body",
                        "references": {"r": "x"},
                        "scripts": {},
                    }
                },
            )

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.load_skill("/p", include_references=False, include_scripts=False)
        finally:
            _stop(c)
        assert isinstance(result, SkillEnvelope)
        assert result.body == "# Body"
        assert result.meta.name == "t1"
        assert result.references["r"] == b"x"
        assert captured[0] == {"path": "/p", "include_references": False, "include_scripts": False}

    async def test_load_skill_missing_skill_key_returns_empty_envelope(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={})

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.load_skill("/p")
        finally:
            _stop(c)
        assert isinstance(result, SkillEnvelope)
        assert result.body == ""
        assert result.meta == SkillMeta()


class TestIngestSkill:
    async def test_ingest_skill_with_references_and_scripts_decodes_bytes(self) -> None:
        captured: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(json.loads(req.content))
            return httpx.Response(
                200,
                json={"path": "/p", "content_sha256": "abc", "created": True},
            )

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.ingest_skill(
                path="/p",
                body="# body",
                references={"r.md": b"ref"},
                scripts={"s.sh": b"scr"},
            )
        finally:
            _stop(c)
        assert isinstance(result, SkillIngestResponse)
        assert result.path == "/p"
        assert result.content_sha256 == "abc"
        assert result.created is True
        assert captured[0]["references"] == {"r.md": "ref"}
        assert captured[0]["scripts"] == {"s.sh": "scr"}

    async def test_ingest_skill_none_references_and_scripts_send_empty_dicts(self) -> None:
        captured: list[dict[str, Any]] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(json.loads(req.content))
            return httpx.Response(200, json={})

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.ingest_skill(path="/p", body="x")
        finally:
            _stop(c)
        assert captured[0]["references"] == {}
        assert captured[0]["scripts"] == {}
        assert result.path == ""
        assert result.content_sha256 == ""
        assert result.created is False

    async def test_ingest_skill_falsy_response_fields_use_defaults(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"path": None, "content_sha256": None, "created": None})

        c = _make_client_with_transport(httpx.MockTransport(handler))
        try:
            result = await c.ingest_skill(path="/p", body="x")
        finally:
            _stop(c)
        assert result.path == ""
        assert result.content_sha256 == ""
        assert result.created is False

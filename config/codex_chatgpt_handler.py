"""LiteLLM custom handler for Codex/ChatGPT OAuth authentication.

The handler uses the Codex CLI credential store as the source of truth:
``~/.codex/auth.json`` (or ``CODEX_AUTH_PATH`` / ``CODEX_HOME``). Unlike
LiteLLM's native ``chatgpt`` provider, it does not maintain a second token
store. Refreshes are written back to the Codex auth file atomically so Codex
and Decepticon do not race through copied refresh tokens.
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import litellm
from litellm import CustomLLM, ModelResponse

CHATGPT_AUTH_BASE = "https://auth.openai.com"
CHATGPT_OAUTH_TOKEN_URL = f"{CHATGPT_AUTH_BASE}/oauth/token"
CHATGPT_API_BASE = "https://chatgpt.com/backend-api/codex"
CHATGPT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_EXPIRY_SKEW_SECONDS = 60

DEFAULT_ORIGINATOR = "codex_cli_rs"
DEFAULT_USER_AGENT = "codex_cli_rs/0.0.0 (Unknown 0; unknown) unknown"

_cached_auth: dict[str, Any] | None = None


def _codex_auth_path() -> Path:
    explicit = os.environ.get("CODEX_AUTH_PATH", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    codex_home = os.environ.get("CODEX_HOME", "").strip()
    if codex_home:
        return Path(codex_home).expanduser() / "auth.json"
    return Path(os.path.expanduser("~/.codex/auth.json"))


def _load_auth() -> dict[str, Any]:
    global _cached_auth  # noqa: PLW0603
    path = _codex_auth_path()
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise litellm.AuthenticationError(
            message=f"Codex ChatGPT credentials not found at {path}. Run 'codex login'.",
            model="auth",
            llm_provider="auth",
        ) from exc
    except (json.JSONDecodeError, OSError) as exc:
        raise litellm.AuthenticationError(
            message=f"Could not read Codex ChatGPT credentials at {path}: {exc}",
            model="auth",
            llm_provider="auth",
        ) from exc

    tokens = raw.get("tokens")
    if not isinstance(tokens, dict) or not all(
        tokens.get(k) for k in ("access_token", "refresh_token", "id_token")
    ):
        raise litellm.AuthenticationError(
            message=(
                f"Codex ChatGPT credentials at {path} are missing "
                "tokens.access_token, tokens.refresh_token, or tokens.id_token. "
                "Run 'codex login'."
            ),
            model="auth",
            llm_provider="auth",
        )
    _cached_auth = raw
    return raw


def _write_auth(auth: dict[str, Any]) -> None:
    path = _codex_auth_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.decepticon.tmp")
    tmp.write_text(json.dumps(auth, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except Exception:
        return {}


def _token_expired(access_token: str) -> bool:
    exp = _decode_jwt_claims(access_token).get("exp")
    if not isinstance(exp, (int, float)):
        return True
    return time.time() >= float(exp) - TOKEN_EXPIRY_SKEW_SECONDS


def _extract_account_id(id_token: str | None, access_token: str | None) -> str | None:
    for token in (id_token, access_token):
        if not token:
            continue
        auth_claims = _decode_jwt_claims(token).get("https://api.openai.com/auth")
        if isinstance(auth_claims, dict):
            account_id = auth_claims.get("chatgpt_account_id")
            if isinstance(account_id, str) and account_id:
                return account_id
    return None


def _refresh_tokens(auth: dict[str, Any]) -> dict[str, Any]:
    tokens = auth["tokens"]
    try:
        resp = httpx.post(
            CHATGPT_OAUTH_TOKEN_URL,
            json={
                "client_id": CHATGPT_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": tokens["refresh_token"],
                "scope": "openid profile email",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as exc:
        raise litellm.AuthenticationError(
            message=(
                "Codex ChatGPT refresh token failed. Run 'codex logout' and "
                f"'codex login'. Underlying: {exc.response.text}"
            ),
            model="auth",
            llm_provider="auth",
        ) from exc
    except Exception as exc:
        raise litellm.AuthenticationError(
            message=f"Codex ChatGPT token refresh failed: {exc}",
            model="auth",
            llm_provider="auth",
        ) from exc

    access_token = data.get("access_token")
    id_token = data.get("id_token")
    if not access_token or not id_token:
        raise litellm.AuthenticationError(
            message=f"Codex ChatGPT refresh response missing fields: {data}",
            model="auth",
            llm_provider="auth",
        )

    tokens["access_token"] = access_token
    tokens["id_token"] = id_token
    tokens["refresh_token"] = data.get("refresh_token", tokens["refresh_token"])
    account_id = _extract_account_id(id_token, access_token)
    if account_id:
        tokens["account_id"] = account_id
    auth["auth_mode"] = "chatgpt"
    auth["last_refresh"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    _write_auth(auth)
    return auth


def get_codex_access_token(force_refresh: bool = False) -> tuple[str, str | None]:
    auth = _load_auth()
    token = auth["tokens"]["access_token"]
    if force_refresh or _token_expired(token):
        auth = _refresh_tokens(auth)
        token = auth["tokens"]["access_token"]
    tokens = auth["tokens"]
    account_id = tokens.get("account_id") or _extract_account_id(tokens.get("id_token"), token)
    return token, account_id


def _headers(access_token: str, account_id: str | None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "content-type": "application/json",
        "accept": "text/event-stream",
        "originator": os.environ.get("CHATGPT_ORIGINATOR", DEFAULT_ORIGINATOR),
        "user-agent": os.environ.get("CHATGPT_USER_AGENT", DEFAULT_USER_AGENT),
    }
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    return headers


def _message_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                text = block.get("text") or block.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return str(content)


def _responses_input(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None]:
    input_items: list[dict[str, Any]] = []
    instructions: list[str] = []
    for msg in messages:
        role = msg.get("role")
        if role == "system":
            text = _message_text(msg.get("content"))
            if text:
                instructions.append(text)
            continue
        if role == "tool":
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": msg.get("tool_call_id") or "tool_call",
                    "output": _message_text(msg.get("content")),
                }
            )
            continue
        if role == "assistant" and msg.get("tool_calls"):
            for tc in msg.get("tool_calls") or []:
                func = tc.get("function", {}) if isinstance(tc, dict) else {}
                input_items.append(
                    {
                        "type": "function_call",
                        "call_id": tc.get("id") or f"call_{func.get('name', 'tool')}",
                        "name": func.get("name") or tc.get("name") or "tool",
                        "arguments": func.get("arguments") or json.dumps(tc.get("args", {})),
                    }
                )
            continue
        mapped_role = "assistant" if role == "assistant" else "user"
        input_items.append({"role": mapped_role, "content": _message_text(msg.get("content"))})
    return input_items, "\n\n".join(instructions) if instructions else None


def _responses_tools(tools: Any) -> list[dict[str, Any]] | None:
    if not tools:
        return None
    out = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
            fn = tool["function"]
            out.append(
                {
                    "type": "function",
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        else:
            out.append(tool)
    return out


def _request_body(
    model: str, messages: list[dict[str, Any]], optional_params: dict[str, Any] | None
) -> dict[str, Any]:
    opts = optional_params or {}
    input_items, instructions = _responses_input(messages)
    body: dict[str, Any] = {
        "model": model.split("/", 1)[-1] if "/" in model else model,
        "input": input_items,
        "stream": True,
        "store": False,
        "include": ["reasoning.encrypted_content"],
    }
    if instructions:
        body["instructions"] = instructions
    tools = _responses_tools(opts.get("tools"))
    if tools:
        body["tools"] = tools
    if opts.get("tool_choice"):
        body["tool_choice"] = opts["tool_choice"]
    if opts.get("reasoning"):
        body["reasoning"] = opts["reasoning"]
    return body


def _completed_payload(resp: httpx.Response) -> dict[str, Any]:
    error_message = None
    for line in resp.text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        data = line.removeprefix("data:").strip()
        if not data or data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError:
            continue
        event_type = event.get("type")
        if event_type == "response.completed" and isinstance(event.get("response"), dict):
            return event["response"]
        if event_type in {"response.failed", "error"}:
            err = event.get("error") or (event.get("response") or {}).get("error")
            error_message = err.get("message") if isinstance(err, dict) else str(err)
    raise litellm.APIError(
        status_code=resp.status_code,
        message=error_message or resp.text,
        model="auth",
        llm_provider="auth",
    )


def _model_response(model: str, payload: dict[str, Any]) -> ModelResponse:
    text_parts: list[str] = []
    tool_calls: list[dict[str, Any]] = []
    for item in payload.get("output") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "message":
            for block in item.get("content") or []:
                if isinstance(block, dict) and block.get("type") in {"output_text", "text"}:
                    text = block.get("text")
                    if isinstance(text, str):
                        text_parts.append(text)
        elif item.get("type") == "function_call":
            tool_calls.append(
                {
                    "id": item.get("call_id") or item.get("id") or f"call_{len(tool_calls)}",
                    "type": "function",
                    "function": {
                        "name": item.get("name", ""),
                        "arguments": item.get("arguments", "{}"),
                    },
                }
            )
    message: dict[str, Any] = {"role": "assistant", "content": "\n".join(text_parts) or None}
    if tool_calls:
        message["tool_calls"] = tool_calls
    usage = payload.get("usage") or {}
    input_tokens = usage.get("input_tokens", 0) or 0
    output_tokens = usage.get("output_tokens", 0) or 0
    return ModelResponse(
        id=payload.get("id", f"chatcmpl-{model}"),
        model=model,
        choices=[
            {
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if tool_calls else "stop",
            }
        ],
        usage={
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": usage.get("total_tokens", input_tokens + output_tokens),
        },
    )


class CodexChatGPTCustomHandler(CustomLLM):
    """LiteLLM custom handler for ``auth/gpt-*`` routes."""

    def completion(
        self,
        model: str,
        messages: list[dict[str, Any]],
        api_base: str | None = None,
        custom_prompt_dict: dict[str, Any] | None = None,
        model_response: ModelResponse | None = None,
        print_verbose: Any = None,
        encoding: Any = None,
        logging_obj: Any = None,
        optional_params: dict[str, Any] | None = None,
        acompletion: bool | None = None,
        timeout: float | None = None,
        litellm_params: dict[str, Any] | None = None,
        logger_fn: Any = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        body = _request_body(model, messages, optional_params)
        api_root = (api_base or os.environ.get("CHATGPT_API_BASE") or CHATGPT_API_BASE).rstrip("/")

        for attempt in range(2):
            access_token, account_id = get_codex_access_token(force_refresh=attempt == 1)
            resp = httpx.post(
                f"{api_root}/responses",
                json=body,
                headers={**_headers(access_token, account_id), **(headers or {})},
                timeout=timeout or 600,
            )
            if resp.status_code != 401:
                break
        if resp.status_code == 401:
            raise litellm.AuthenticationError(
                message=(
                    "Codex ChatGPT authentication was rejected. Run 'codex logout' "
                    f"and 'codex login'. Underlying: {resp.text}"
                ),
                model=model,
                llm_provider="auth",
            )
        if resp.status_code >= 400:
            raise litellm.APIError(
                status_code=resp.status_code,
                message=f"ChatGPT Codex API error: {resp.text}",
                model=model,
                llm_provider="auth",
            )
        return _model_response(model, _completed_payload(resp))

    async def acompletion(self, *args: Any, **kwargs: Any) -> ModelResponse:
        import asyncio
        import functools

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, functools.partial(self.completion, *args, **kwargs))

    def _response_to_chunks(self, response: ModelResponse) -> list[dict[str, Any]]:
        choice = response.choices[0]
        msg = choice.message if hasattr(choice, "message") else choice.get("message", {})
        content = msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", "")
        raw_tool_calls = (
            msg.get("tool_calls", []) if isinstance(msg, dict) else getattr(msg, "tool_calls", [])
        )
        usage = {
            "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
            "completion_tokens": response.usage.completion_tokens if response.usage else 0,
            "total_tokens": response.usage.total_tokens if response.usage else 0,
        }
        if raw_tool_calls:
            chunks = []
            if content:
                chunks.append(
                    {
                        "text": content,
                        "is_finished": False,
                        "finish_reason": "",
                        "index": 0,
                        "tool_use": None,
                        "usage": None,
                    }
                )
            for index, tool_call in enumerate(raw_tool_calls):
                if not isinstance(tool_call, dict):
                    tool_call = {
                        "id": getattr(tool_call, "id", f"call_{index}"),
                        "type": "function",
                        "function": getattr(tool_call, "function", {}),
                    }
                chunks.append(
                    {
                        "text": "",
                        "is_finished": index == len(raw_tool_calls) - 1,
                        "finish_reason": "tool_calls" if index == len(raw_tool_calls) - 1 else "",
                        "index": 0,
                        "tool_use": {**tool_call, "index": index},
                        "usage": usage if index == len(raw_tool_calls) - 1 else None,
                    }
                )
            return chunks
        return [
            {
                "text": content or "",
                "is_finished": True,
                "finish_reason": choice.get("finish_reason", "stop")
                if isinstance(choice, dict)
                else getattr(choice, "finish_reason", "stop"),
                "index": 0,
                "tool_use": None,
                "usage": usage,
            }
        ]

    def streaming(self, *args: Any, **kwargs: Any) -> Iterator[dict[str, Any]]:
        yield from self._response_to_chunks(self.completion(*args, **kwargs))

    async def astreaming(self, *args: Any, **kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        response = await self.acompletion(*args, **kwargs)
        for chunk in self._response_to_chunks(response):
            yield chunk


codex_chatgpt_handler_instance = CodexChatGPTCustomHandler()

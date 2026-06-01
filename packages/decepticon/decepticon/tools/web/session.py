"""Cookie / session entropy + framework fingerprint.

Each cookie the agent sees is analysed for:

- Framework identity (Flask, Django, Rails, Express, Laravel, ASP.NET,
  PHP, Spring, JWT, Rack...)
- Structural decoding (base64, URL, JSON, signed-cookie components)
- Shannon entropy + character-class distribution (predictability)
- Secure flag / HttpOnly / SameSite advisory
- Short-session / long-session cookie classification

The output is intentionally loud — a defender would demote, but a bug
hunter wants every plausible weak signal surfaced.
"""

from __future__ import annotations

import base64
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CookieAnalysis:
    name: str
    value: str
    framework: str | None = None
    format: str = "opaque"
    decoded: Any = None
    shannon_entropy: float = 0.0
    char_classes: dict[str, int] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value[:120] + "..." if len(self.value) > 120 else self.value,
            "framework": self.framework,
            "format": self.format,
            "decoded": self.decoded,
            "shannon_entropy": round(self.shannon_entropy, 3),
            "char_classes": dict(self.char_classes),
            "findings": list(self.findings),
        }


# ── Framework fingerprint table ─────────────────────────────────────────

_FRAMEWORK_BY_NAME: dict[str, str] = {
    "sessionid": "Django",
    "csrftoken": "Django",
    "session": "Flask",
    "_session_id": "Rails",
    "_rails_session": "Rails",
    "rack.session": "Rack",
    "connect.sid": "Express (connect)",
    "express.sid": "Express",
    "laravel_session": "Laravel",
    "xsrf-token": "Angular",
    "asp.net_sessionid": "ASP.NET",
    ".aspxauth": "ASP.NET Forms",
    "phpsessid": "PHP",
    "jsessionid": "Java Servlet",
    "ci_session": "CodeIgniter",
    "symfony": "Symfony",
    "yii_csrf_token": "Yii2",
    "dmg_session": "Spring Security",
    "remember_token": "Devise / custom",
}


def _framework(name: str) -> str | None:
    return _FRAMEWORK_BY_NAME.get(name.lower())


# ── Entropy + char-class ────────────────────────────────────────────────


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _classify(value: str) -> dict[str, int]:
    """Bucket cookie characters.

    ``hex`` is tracked as an additional signal count rather than a mutually
    exclusive bucket so obviously hex-encoded cookies remain visible even
    though their characters are also lowercase/uppercase/digits.
    """
    classes = {"lower": 0, "upper": 0, "digit": 0, "base64": 0, "hex": 0, "other": 0}
    for ch in value:
        if ch in "0123456789abcdefABCDEF":
            classes["hex"] += 1
        if ch.islower():
            classes["lower"] += 1
        elif ch.isupper():
            classes["upper"] += 1
        elif ch.isdigit():
            classes["digit"] += 1
        elif ch in "+/=-_":
            classes["base64"] += 1
        else:
            classes["other"] += 1
    return classes


# ── Decoders ────────────────────────────────────────────────────────────


_B64_RE = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")


def _try_b64_json(value: str) -> Any | None:
    if not _B64_RE.match(value):
        return None
    try:
        pad = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + pad)
        text = raw.decode("utf-8", errors="replace")
        return json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None


def _try_jwt(value: str) -> dict[str, Any] | None:
    if value.count(".") != 2:
        return None
    try:
        header_b64, body_b64, _sig = value.split(".")
        pad_h = "=" * (-len(header_b64) % 4)
        pad_b = "=" * (-len(body_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64 + pad_h).decode())
        body = json.loads(base64.urlsafe_b64decode(body_b64 + pad_b).decode())
        return {"header": header, "body": body}
    except (ValueError, json.JSONDecodeError):
        return None


# ── Main entry ─────────────────────────────────────────────────────────


def analyze_cookie(
    name: str,
    value: str,
    *,
    secure: bool = False,
    http_only: bool = False,
    same_site: str | None = None,
) -> CookieAnalysis:
    """Analyse a single cookie for framework, structure, and weak entropy."""
    analysis = CookieAnalysis(
        name=name,
        value=value,
        framework=_framework(name),
        shannon_entropy=shannon_entropy(value),
        char_classes=_classify(value),
    )

    # Try JWT first — it's the highest-value structure
    jwt_guess = _try_jwt(value)
    if jwt_guess is not None:
        analysis.format = "jwt"
        analysis.decoded = jwt_guess
        analysis.findings.append("cookie is a JWT — run parse_token for deep analysis")
    else:
        b64_json = _try_b64_json(value)
        if b64_json is not None:
            analysis.format = "base64-json"
            analysis.decoded = b64_json
            analysis.findings.append("cookie is base64-encoded JSON — signed-cookie candidate")
        elif _B64_RE.match(value) and len(value) >= 16:
            analysis.format = "base64-opaque"

    # Entropy-based weak-random detection
    if analysis.shannon_entropy < 3.0 and analysis.format == "opaque":
        analysis.findings.append(
            f"low Shannon entropy ({analysis.shannon_entropy:.2f}) — predictable session ID candidate"
        )
    if len(value) < 12:
        analysis.findings.append(f"cookie value too short ({len(value)} chars)")

    # Transport-security advisory
    if not secure:
        analysis.findings.append("Secure flag not set — cookie can be sent over plain HTTP")
    if not http_only and analysis.framework is not None:
        analysis.findings.append("HttpOnly not set on a session cookie — XSS can steal it")
    if same_site is None or same_site.lower() == "none":
        analysis.findings.append(
            "SameSite not set or None — cookie MAY be sent on cross-site requests (CSRF risk)"
        )

    return analysis


# ── CSRF-aware login helper ─────────────────────────────────────────────


def login_with_csrf(
    login_url: str,
    username: str,
    password: str,
    *,
    token_field: str | None = None,
    username_field: str = "username",
    password_field: str = "password",
    submit_field: str | None = None,
    submit_value: str | None = None,
    extra_data: dict[str, str] | None = None,
    success_indicator: str | None = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """Login to a PHP/web form that uses CSRF tokens.

    GETs the login page, extracts hidden CSRF token fields, POSTs
    credentials with the token, and maintains session cookies.

    Args:
        login_url: Full URL to the login page (e.g. http://target/login.php)
        username: Login username
        password: Login password
        token_field: Specific hidden field name to extract (auto-detect if None)
        username_field: Form field name for username (default: "username")
        password_field: Form field name for password (default: "password")
        submit_field: Submit button field name (auto-detect if None)
        submit_value: Submit button value (auto-detect if None)
        extra_data: Additional form fields to include in POST
        success_indicator: String in response URL or body that indicates success
        timeout: Request timeout in seconds

    Returns:
        dict with keys: success (bool), session_cookies (dict), response_url (str),
        status_code (int), token_found (bool), error (str|None)
    """
    import requests

    result = {
        "success": False,
        "session_cookies": {},
        "response_url": "",
        "status_code": 0,
        "token_found": False,
        "error": None,
    }

    session = requests.Session()

    try:
        # Step 1: GET login page and extract CSRF token
        r = session.get(login_url, timeout=timeout)
        r.raise_for_status()
        html = r.text

        # Extract CSRF token
        token_name = None
        token_value = None

        if token_field:
            # Look for specific field
            m = re.search(
                rf'name=["\']' + re.escape(token_field) + rf'["\']\s+value=["\']([^"\']+)["\']',
                html,
                re.IGNORECASE,
            )
            if not m:
                m = re.search(
                    rf'value=["\']([^"\']+)["\']\s+name=["\']' + re.escape(token_field) + rf'["\']',
                    html,
                    re.IGNORECASE,
                )
            if m:
                token_name = token_field
                token_value = m.group(1)
        else:
            # Auto-detect common CSRF token patterns
            csrf_patterns = [
                (r'name=["\']user_token["\']\s+value=["\']([a-f0-9]+)["\']', "user_token"),
                (r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', "csrf_token"),
                (r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']', "_token"),
                (r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']', "csrfmiddlewaretoken"),
                (r'name=["\']authenticity_token["\']\s+value=["\']([^"\']+)["\']', "authenticity_token"),
                (r'name=["\']__RequestVerificationToken["\']\s+value=["\']([^"\']+)["\']', "__RequestVerificationToken"),
            ]
            for pattern, name in csrf_patterns:
                m = re.search(pattern, html, re.IGNORECASE)
                if m:
                    token_name = name
                    token_value = m.group(1)
                    break

            # Fallback: any hidden input with "token" in the name
            if not token_name:
                m = re.search(
                    r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*token[^"\']*)["\'][^>]*value=["\']([^"\']+)["\']',
                    html,
                    re.IGNORECASE,
                )
                if not m:
                    m = re.search(
                        r'<input[^>]*name=["\']([^"\']*token[^"\']*)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']',
                        html,
                        re.IGNORECASE,
                    )
                if m:
                    token_name = m.group(1)
                    token_value = m.group(2)

        if not token_value:
            result["error"] = "No CSRF token found on login page"
            return result

        result["token_found"] = True

        # Step 2: Detect submit button
        if not submit_field:
            submit_match = re.search(
                r'<input[^>]*type=["\']submit["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
                html,
                re.IGNORECASE,
            )
            if not submit_match:
                submit_match = re.search(
                    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']submit["\'][^>]*value=["\']([^"\']*)["\']',
                    html,
                    re.IGNORECASE,
                )
            if submit_match:
                submit_field = submit_match.group(1)
                submit_value = submit_match.group(2) or submit_field

        # Step 3: Build POST data
        post_data: dict[str, str] = {
            username_field: username,
            password_field: password,
        }
        if token_name:
            post_data[token_name] = token_value
        if submit_field:
            post_data[submit_field] = submit_value or submit_field
        if extra_data:
            post_data.update(extra_data)

        # Step 4: POST login
        r2 = session.post(login_url, data=post_data, allow_redirects=True, timeout=timeout)

        result["status_code"] = r2.status_code
        result["response_url"] = r2.url
        result["session_cookies"] = dict(session.cookies)

        # Step 5: Determine success
        if success_indicator:
            result["success"] = success_indicator in r2.url or success_indicator in r2.text
        else:
            # Heuristic: redirected away from login page = success
            login_path = login_url.split("?")[0].rsplit("/", 1)[-1]
            result["success"] = login_path not in r2.url

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result

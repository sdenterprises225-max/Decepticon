#!/usr/bin/env python3
"""Standalone CSRF-aware login script for DVWA and similar PHP forms.

Usage:
    python3 login_with_csrf.py <login_url> <username> <password> [--token-field user_token]

Example:
    python3 login_with_csrf.py http://dvwa-test/login.php admin password

Returns JSON with: success, session_cookies, response_url, token_found, error
"""

import argparse
import json
import re
import sys

try:
    import requests
except ImportError:
    print(json.dumps({"error": "requests module not installed. Run: apt-get install -y python3-requests"}))
    sys.exit(1)


def login_with_csrf(
    login_url: str,
    username: str,
    password: str,
    *,
    token_field: str = None,
    username_field: str = "username",
    password_field: str = "password",
    submit_field: str = None,
    submit_value: str = None,
    timeout: int = 15,
) -> dict:
    """Login to a PHP/web form that uses CSRF tokens.
    
    GETs the login page, extracts hidden CSRF token fields, POSTs
    credentials with the token, and maintains session cookies.
    """
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
            submit_tag = re.search(
                r'<input[^>]*type=["\']submit["\'][^>]*>',
                html,
                re.IGNORECASE,
            )
            if submit_tag:
                tag = submit_tag.group(0)
                name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
                value_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                if name_m:
                    submit_field = name_m.group(1)
                    submit_value = value_m.group(1) if value_m else submit_field

        # Step 3: Build POST data
        post_data = {
            username_field: username,
            password_field: password,
        }
        if token_name:
            post_data[token_name] = token_value
        if submit_field:
            post_data[submit_field] = submit_value or submit_field

        # Step 4: POST login
        r2 = session.post(login_url, data=post_data, allow_redirects=True, timeout=timeout)

        result["status_code"] = r2.status_code
        result["response_url"] = r2.url
        result["session_cookies"] = dict(session.cookies)

        # Step 5: Determine success
        # Heuristic: redirected away from login page = success
        login_path = login_url.split("?")[0].rsplit("/", 1)[-1]
        result["success"] = login_path not in r2.url

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSRF-aware login script")
    parser.add_argument("login_url", help="Full URL to login page")
    parser.add_argument("username", help="Username")
    parser.add_argument("password", help="Password")
    parser.add_argument("--token-field", help="Specific CSRF token field name")
    parser.add_argument("--username-field", default="username", help="Username field name")
    parser.add_argument("--password-field", default="password", help="Password field name")
    
    args = parser.parse_args()
    
    result = login_with_csrf(
        args.login_url,
        args.username,
        args.password,
        token_field=args.token_field,
        username_field=args.username_field,
        password_field=args.password_field,
    )
    
    print(json.dumps(result, indent=2))

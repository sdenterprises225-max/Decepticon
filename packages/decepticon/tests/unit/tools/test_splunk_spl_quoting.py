from __future__ import annotations

from decepticon.tools.defense.splunk import (
    _needs_spl_quoting,
    _spl_escape,
    sigma_to_spl,
)


def _rule_contains(value: str) -> dict:
    return {
        "detection": {
            "sel": {"CommandLine|contains": value},
            "condition": "sel",
        }
    }


def _rule_startswith(value: str) -> dict:
    return {
        "detection": {
            "sel": {"Image|startswith": value},
            "condition": "sel",
        }
    }


def _rule_endswith(value: str) -> dict:
    return {
        "detection": {
            "sel": {"Image|endswith": value},
            "condition": "sel",
        }
    }


def test_contains_with_space_produces_quoted_wildcard():
    spl = sigma_to_spl(_rule_contains("Invoke-Mimikatz -DumpCreds"))
    assert 'CommandLine="*Invoke-Mimikatz -DumpCreds*"' in spl


def test_startswith_with_space_produces_quoted_wildcard():
    spl = sigma_to_spl(_rule_startswith("C:\\Program Files\\evil.exe"))
    assert 'Image="C:\\\\Program Files\\\\evil.exe*"' in spl


def test_endswith_with_space_produces_quoted_wildcard():
    spl = sigma_to_spl(_rule_endswith("\\program files\\x.exe"))
    assert 'Image="*\\\\program files\\\\x.exe"' in spl


def test_contains_space_value_is_single_spl_term():
    spl = sigma_to_spl(_rule_contains("foo bar"))
    assert " ".join(spl.split()).count("CommandLine=") == 1
    assert '"*foo bar*"' in spl


def test_contains_with_embedded_quote_is_escaped():
    spl = sigma_to_spl(_rule_contains('say "hello" now'))
    assert '\\"hello\\"' in spl or 'say \\"hello\\"' in spl


def test_contains_simple_value_unchanged():
    spl = sigma_to_spl(_rule_contains("DownloadString"))
    assert "CommandLine=*DownloadString*" in spl


def test_endswith_simple_value_unchanged():
    spl = sigma_to_spl(_rule_endswith("\\powershell.exe"))
    assert "Image=*\\powershell.exe" in spl


def test_spl_escape_backslash_and_quote():
    assert _spl_escape("a\\b") == "a\\\\b"
    assert _spl_escape('a"b') == 'a\\"b'


def test_needs_spl_quoting_detects_space_and_quote():
    assert _needs_spl_quoting("foo bar")
    assert _needs_spl_quoting('foo"bar')
    assert not _needs_spl_quoting("foobar")
    assert not _needs_spl_quoting("foo\\bar")

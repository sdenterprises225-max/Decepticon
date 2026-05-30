from __future__ import annotations

import pytest

from decepticon.middleware._command_targets import _is_valid_target, extract_targets


@pytest.mark.parametrize(
    "command,expected_host",
    [
        ("curl https://user:pass@evil.example/", "evil.example"),
        ("curl ftp://anonymous@out.example", "out.example"),
        ("wget http://attacker%40svc@hidden.example/x", "hidden.example"),
        ("smbclient smb://user@10.20.30.40/share", "10.20.30.40"),
    ],
)
def test_userinfo_does_not_hide_the_real_host(command, expected_host):
    assert any(target == expected_host for target in extract_targets(command))


def test_userinfo_host_still_strips_port():
    targets = extract_targets("curl https://user:pass@example.com:8443/admin")
    assert any(target == "example.com" for target in targets)
    assert all(target != "example.com:8443" for target in targets)


def test_plain_url_host_unchanged():
    assert any(target == "example.com" for target in extract_targets("curl https://example.com/path?q=1"))


@pytest.mark.parametrize(
    "host",
    ["evil.zip", "target.sh", "pay.md", "exploit.py", "domain.pl", "docs.pub"],
)
def test_tld_colliding_hosts_are_extracted(host):
    assert _is_valid_target(host) is True
    assert any(target == host for target in extract_targets(f"curl https://{host}/"))


@pytest.mark.parametrize(
    "fname",
    ["key.pem", "scan.txt", "creds.json", "out.log", "dump.pcap", "data.csv", "archive.tar"],
)
def test_local_file_arguments_are_still_excluded(fname):
    assert _is_valid_target(fname) is False
    assert all(target != fname for target in extract_targets(f"nmap -oA {fname} 10.0.0.1"))


def test_oa_output_file_excluded_but_ip_kept():
    targets = extract_targets("nmap -oA report.txt 10.0.0.1")
    assert targets == {"10.0.0.1"}

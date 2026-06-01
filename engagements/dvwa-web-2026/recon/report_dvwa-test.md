# Recon Report: http://dvwa-test:80

**Date:** 2026-06-01  
**Target:** dvwa-test:80

## Service & Stack Inventory

| Component | Observation | Source |
|-----------|-------------|--------|
| Web Server | Apache/2.4.25 (Debian) | HTTP `Server:` header |
| OS Fingerprint | Debian Linux | Apache banner `(Debian)` |
| Runtime | PHP (session cookies present) | `Set-Cookie: PHPSESSID=...` |
| Application | Damn Vulnerable Web Application (DVWA) v1.10 *Development* | HTML `<title>` tags |
| Security Level | `low` (cookie set) | `Set-Cookie: security=low` |

## Endpoints Observed

| Path | Status | Response Size | Notes |
|------|--------|---------------|-------|
| `/` | 302 Found | - | Redirects to `login.php`; sets `PHPSESSID` and `security=low` cookies |
| `/login.php` | 200 OK | ~1KB | DVWA login page; references `dvwa/css/login.css`, `dvwa/images/login_logo.png` |
| `/setup.php` | 200 OK | ~2KB | DVWA setup page; accessible without auth |
| `/index.php` | 302 (assumed) | - | Redirects to login (empty body in probe) |
| `/about.php` | 200 OK | ~2KB | DVWA about page; static content |

## Internal References

- Static assets under `/dvwa/css/`, `/dvwa/images/`, `/dvwa/js/`
- Favicon: `/favicon.ico`

## High Priority Findings

1. **DVWA v1.10 Development** exposed at root — intentionally vulnerable application.
2. **Security level set to `low`** via cookie — suggests minimal input validation.
3. **`/setup.php` accessible** — may allow database reset/reinitialization.

---

**RECON_OBSERVATIONS:** DVWA v1.10 on Apache/2.4.25 (Debian) with PHP sessions; security=low cookie set; /setup.php, /login.php, /about.php accessible.

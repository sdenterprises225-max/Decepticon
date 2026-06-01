# DVWA Reconnaissance Summary

**Target**: http://dvwa-test:80  
**Date**: 2026-06-01  
**Engagement**: dvwa-web-2026

---

## Service & Stack Inventory

| Component | Version / Details | Source |
|-----------|-------------------|--------|
| Web Server | Apache/2.4.25 (Debian) | HTTP Banner, phpinfo |
| PHP | 7.0.30-0+deb9u1 | phpinfo.php |
| Application | Damn Vulnerable Web Application (DVWA) v1.10 *Development* | HTML Title, Footer |
| OS | Linux 5806a3367466 (Kernel 7.0.5-orbstack) | phpinfo System field |
| Server API | Apache 2.0 Handler | phpinfo |
| Server Address | 192.168.155.6:80 | phpinfo SERVER_ADDR |

---

## Authentication & Session

**Default Credentials Tested**: `admin` / `password`  
**Result**: Login successful (confirmed via `main_menu.html` showing "You have logged in as 'admin'").

**Session Cookies Captured**:
```
PHPSESSID=<session_id>; path=/
security=low; path=/
```

**CSRF Token**:
- Field name: `user_token`
- Location: Hidden input in `login.php`
- Behavior: Session-bound, must be fetched fresh per login attempt
- Example value observed: `e1745af7b26cadbed4a07744e50b8d71`

**Login Request Format**:
```http
POST /login.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<id>

username=admin&password=password&Login=Login&user_token=<fresh_token>
```

---

## Application Structure & Endpoints

### Core Pages Discovered

| Path | Status | Description |
|------|--------|-------------|
| `/` | 302 → login.php | Root redirects to login |
| `/login.php` | 200 | Authentication form with CSRF token |
| `/index.php` | 200 | Main dashboard (requires auth) |
| `/setup.php` | 200 | Database initialization/reset |
| `/security.php` | 200 | Security level configuration |
| `/about.php` | 200 | Application info |
| `/instructions.php` | 200 | Usage guide |
| `/phpinfo.php` | 200 | Full PHP configuration disclosure |
| `/logout.php` | 200 | Session termination |

### Vulnerability Modules Exposed (from main menu)

| Module | Path | Category |
|--------|------|----------|
| Brute Force | `/vulnerabilities/brute/` | Authentication |
| Command Injection | `/vulnerabilities/exec/` | RCE |
| CSRF | `/vulnerabilities/csrf/` | Request Forgery |
| File Inclusion | `/vulnerabilities/fi/` | LFI/RFI |
| File Upload | `/vulnerabilities/upload/` | Unrestricted Upload |
| Insecure CAPTCHA | `/vulnerabilities/captcha/` | Logic Flaw |
| SQL Injection | `/vulnerabilities/sqli/` | Database |
| SQL Injection (Blind) | `/vulnerabilities/sqli_blind/` | Database |
| Weak Session IDs | `/vulnerabilities/view_source_all/` | Session |
| XSS (DOM) | `/vulnerabilities/xss_d/` | Cross-Site Scripting |
| XSS (Reflected) | `/vulnerabilities/xss_r/` | Cross-Site Scripting |
| XSS (Stored) | `/vulnerabilities/xss_s/` | Cross-Site Scripting |
| CSP Bypass | `/vulnerabilities/csp/` | Content Security Policy |
| JavaScript | `/vulnerabilities/javascript/` | Client-side |

### Directory Structure Observed

```
/dvwa/
  css/
    login.css
    main.css
  images/
    logo.png
    login_logo.png
  js/
    dvwaPage.js
    add_event_listeners.js
  favicon.ico
```

---

## Security Configuration

**Current Security Level**: `low`  
**PHPIDS (WAF)**: `disabled`  
**Authenticated User**: `admin`

**Security Headers Observed**:
- `Cache-Control: no-store, no-cache, must-revalidate`
- `Pragma: no-cache`
- `Expires: Thu, 19 Nov 1981 08:52:00 GMT`

**Missing/Weak Headers**:
- No `X-Frame-Options` (clickjacking potential)
- No `X-Content-Type-Options` (MIME sniffing)
- No `Strict-Transport-Security` (HSTS)
- No `Content-Security-Policy` on most pages (CSP module exists but not enforced globally)

---

## High-Priority Observations

1. **PHP 7.0.30** is end-of-life (EOL since Dec 2018) with multiple known CVEs.
2. **phpinfo.php** is publicly accessible, exposing:
   - Full server paths (`/etc/apache2`)
   - Server IP (`192.168.155.6`)
   - All `$_SERVER` variables
   - Loaded PHP extensions and configurations
3. **Security level is `low`** — all vulnerability modules are configured with minimal protections.
4. **Default credentials work** — `admin/password` provides full administrative access.
5. **CSRF tokens are session-bound** — must be scraped per-session for automated exploitation.
6. **14 distinct vulnerability modules** are exposed and accessible post-authentication.

---

## Raw Evidence Files

All raw outputs saved to `/workspace/recon/`:

| File | Description |
|------|-------------|
| `banner_headers.txt` | HTTP response headers from root |
| `login_full.html` | Full login page HTML |
| `main_menu.html` | Authenticated main menu (shows all vuln modules) |
| `phpinfo.html` | Complete phpinfo() output (89KB) |
| `security_page.html` | Security configuration page |
| `instructions.html` | Application instructions |
| `cookies.txt` | Captured session cookies |
| `login_response.html` | Login POST response |
| `nmap_scan.txt` | Port scan results |

---

## RECON_OBSERVATIONS:
Authenticated admin session captured (security=low); PHP 7.0.30 + Apache/2.4.25 exposed via phpinfo; 14 vulnerability modules mapped including SQLi, XSS, RCE, File Upload, and File Inclusion; default credentials admin/password confirmed working; CSRF token mechanism identified (session-bound user_token field).

"""
Module 16: Authentication & Session Testing
Brute force protection, account enumeration, JWT forgery, session security,
password policy, OAuth misconfig, default credentials
"""
import re, time, base64, json, hashlib
import concurrent.futures
from urllib.parse import urlparse, quote

UA = "Mozilla/5.0 (SecureScan/2.0; +https://securescan.io)"
TIMEOUT = 8

def _get(url, method="GET", headers=None, data=None, timeout=None, allow_redirects=True):
    try:
        import requests
        h = {"User-Agent": UA, **(headers or {})}
        t = timeout or TIMEOUT
        if method == "POST":
            return requests.post(url, headers=h, json=data, timeout=t, allow_redirects=allow_redirects)
        return requests.get(url, headers=h, timeout=t, allow_redirects=allow_redirects)
    except Exception:
        return None

def _post_form(url, data, headers=None, timeout=None):
    try:
        import requests
        h = {"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
        return requests.post(url, data=data, headers=h, timeout=timeout or TIMEOUT)
    except Exception:
        return None

# ── Find login endpoints ──────────────────────────────────────────────────────
def find_login_endpoints(base: str) -> list:
    PATHS = ["/login", "/signin", "/auth", "/api/login", "/api/auth", "/api/signin",
             "/admin/login", "/user/login", "/account/login", "/wp-login.php",
             "/administrator", "/api/v1/login", "/api/v1/auth", "/session"]
    found = []
    def chk(path):
        r = _get(f"{base}{path}", allow_redirects=True, timeout=4)
        if r and r.status_code in (200, 405):
            return path
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        found = [x for x in ex.map(chk, PATHS) if x]
    return found

# ── Brute force protection ────────────────────────────────────────────────────
def test_brute_force_protection(base: str, login_paths: list) -> list:
    findings = []
    for path in login_paths[:2]:
        url = f"{base}{path}"
        blocked = False
        for i in range(6):
            r = _post_form(url, {
                "username": "testuser@example.com",
                "password": f"WrongPass{i}!",
                "email":    "testuser@example.com",
            }, timeout=5)
            if not r:
                break
            if r.status_code == 429:
                blocked = True
                break
            if any(x in r.text.lower() for x in ["captcha", "too many", "locked", "blocked", "rate limit"]):
                blocked = True
                break
        if not blocked:
            findings.append({
                "severity": "high",
                "title": f"No brute force protection at {path}",
                "status": "fail",
                "detail": f"Made 6 failed login attempts to {path} with no rate limiting, lockout, or CAPTCHA.",
                "fix": "Implement: (1) rate limiting after 5 failures, (2) account lockout after 10, (3) CAPTCHA, (4) IP throttling.",
            })
        else:
            findings.append({
                "severity": "low",
                "title": f"Brute force protection active at {path}",
                "status": "pass",
                "detail": "Login endpoint returned 429 or lockout message after repeated failures.",
            })
    return findings

# ── Account enumeration ───────────────────────────────────────────────────────
def test_account_enumeration(base: str, login_paths: list) -> list:
    findings = []
    KNOWN_NONEXISTENT = "zzz_nonexistent_user_xyz_99999@notreal.io"
    COMMON_USER       = "admin@example.com"

    for path in login_paths[:2]:
        url = f"{base}{path}"
        r_invalid = _post_form(url, {"username": KNOWN_NONEXISTENT, "password": "WrongPass1!", "email": KNOWN_NONEXISTENT}, timeout=5)
        r_admin   = _post_form(url, {"username": COMMON_USER,       "password": "WrongPass1!", "email": COMMON_USER},       timeout=5)

        if not r_invalid or not r_admin:
            continue

        msg_invalid = r_invalid.text.lower()
        msg_admin   = r_admin.text.lower()

        # Different messages = enumerable
        NOT_FOUND_MSGS = ["user not found", "no account", "email not registered",
                          "doesn't exist", "not found", "unknown email"]
        WRONG_PASS_MSGS = ["incorrect password", "wrong password", "invalid password",
                           "password is wrong", "bad credentials"]

        if any(m in msg_invalid for m in NOT_FOUND_MSGS) or \
           (any(m in msg_admin for m in WRONG_PASS_MSGS) and msg_invalid != msg_admin):
            findings.append({
                "severity": "medium",
                "title": f"Account enumeration possible at {path}",
                "status": "fail",
                "detail": "Different error messages for non-existent vs existing accounts allow username enumeration.",
                "fix": "Use identical error messages: 'Invalid email or password' regardless of whether the account exists.",
            })
        else:
            findings.append({
                "severity": "low",
                "title": f"Account enumeration not detected at {path}",
                "status": "pass",
                "detail": "Error messages appear consistent for valid and invalid accounts.",
            })
    return findings

# ── JWT Security Testing ───────────────────────────────────────────────────────
def test_jwt_security(base: str) -> list:
    findings = []
    r = _get(base)
    if not r:
        return findings

    # Find JWTs in cookies and response headers
    all_cookies = r.cookies
    headers_str = str(r.headers)
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
    tokens_found = re.findall(jwt_pattern, r.text + headers_str)

    for cookie in all_cookies:
        val = cookie.value
        if re.match(jwt_pattern, val):
            tokens_found.append(val)

    for token in tokens_found[:3]:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                continue

            # Decode header
            hdr_pad = parts[0] + "=" * (-len(parts[0]) % 4)
            hdr     = json.loads(base64.urlsafe_b64decode(hdr_pad))
            alg     = hdr.get("alg", "").upper()

            # Algorithm confusion: none
            if alg == "NONE":
                findings.append({
                    "severity": "critical",
                    "title": "JWT uses 'none' algorithm (signature bypass)",
                    "status": "fail",
                    "detail": "JWT header specifies alg=none — signature is not verified.",
                    "fix": "Reject JWTs with alg=none. Whitelist only HS256/RS256.",
                })

            # Weak algorithm
            elif alg in ("HS1", "HS256") and len(parts[2]) < 20:
                findings.append({
                    "severity": "high",
                    "title": f"JWT uses weak/short signature ({alg})",
                    "status": "fail",
                    "detail": "Short or weak JWT signature may be brute-forceable.",
                    "fix": "Use RS256 (asymmetric) or HS256 with a 256-bit+ random secret.",
                })

            # Try none algorithm bypass
            fake_hdr = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
            fake_tok = f"{fake_hdr}.{parts[1]}."
            r_bypass = _get(base, headers={"Authorization": f"Bearer {fake_tok}"}, timeout=5)
            if r_bypass and r_bypass.status_code == 200:
                body = r_bypass.text.lower()
                if any(x in body for x in ["user", "account", "profile", "data", "token"]):
                    findings.append({
                        "severity": "critical",
                        "title": "JWT 'none' algorithm bypass accepted",
                        "status": "fail",
                        "detail": "Server accepted JWT with alg=none and no signature. Authentication bypassed.",
                        "fix": "Explicitly verify JWT algorithm. Reject alg=none. Use a JWT library that enforces algorithm.",
                    })

            # Decode payload and check claims
            pay_pad = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(pay_pad))

            # Sensitive data in payload
            SENSITIVE = ["password", "secret", "key", "credit", "card", "ssn", "token"]
            for k, v in payload.items():
                if any(s in k.lower() for s in SENSITIVE):
                    findings.append({
                        "severity": "high",
                        "title": f"Sensitive data in JWT payload: '{k}'",
                        "status": "fail",
                        "detail": "JWT payload contains sensitive field. JWTs are base64-encoded, not encrypted — anyone can read them.",
                        "fix": "Remove sensitive data from JWT payload. Use JWT encryption (JWE) if necessary.",
                    })

            # No expiry
            if "exp" not in payload:
                findings.append({
                    "severity": "medium",
                    "title": "JWT has no expiry (exp claim missing)",
                    "status": "fail",
                    "detail": "Token never expires — stolen tokens are valid forever.",
                    "fix": "Add 'exp' claim. Use short-lived tokens (15 minutes–1 hour) with refresh tokens.",
                })

        except Exception:
            continue

    # Test weak HS256 secret (common secrets)
    WEAK_SECRETS = ["secret", "password", "123456", "jwt_secret", "your-256-bit-secret",
                    "supersecret", "key", "private", "changeme"]
    for token in tokens_found[:2]:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            import hmac
            header_payload = f"{parts[0]}.{parts[1]}"
            sig_bytes = base64.urlsafe_b64decode(parts[2] + "==")
            for secret in WEAK_SECRETS:
                expected = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
                if sig_bytes == expected:
                    findings.append({
                        "severity": "critical",
                        "title": f"JWT signed with weak secret: '{secret}'",
                        "status": "fail",
                        "detail": f"JWT signature verified with common secret '{secret}'. Attacker can forge any token.",
                        "fix": "Replace with a cryptographically random 256-bit secret. Store in environment variables, never in code.",
                    })
                    break
        except Exception:
            pass

    if not findings:
        findings.append({
            "severity": "low",
            "title": "No JWT vulnerabilities detected",
            "status": "pass",
            "detail": "JWT tokens appear to use secure algorithms and include expiry claims.",
        })
    return findings

# ── Session Security ───────────────────────────────────────────────────────────
def test_session_security(base: str) -> list:
    findings = []
    r = _get(base)
    if not r:
        return findings

    for cookie in r.cookies:
        name = cookie.name.lower()
        if any(x in name for x in ["session", "sess", "sid", "token", "auth", "phpsessid", "jsessionid"]):
            # Check entropy (short session IDs are guessable)
            val = cookie.value
            if len(val) < 16:
                findings.append({
                    "severity": "high",
                    "title": f"Session ID too short: {cookie.name} ({len(val)} chars)",
                    "status": "fail",
                    "detail": "Short session IDs can be brute-forced.",
                    "fix": "Use at least 128-bit (32 hex char) cryptographically random session IDs.",
                })
            # Sequential/predictable ID check
            elif val.isdigit() or val.isnumeric():
                findings.append({
                    "severity": "high",
                    "title": f"Session ID appears numeric/sequential: {cookie.name}",
                    "status": "fail",
                    "detail": "Numeric session IDs may be sequential and guessable.",
                    "fix": "Use cryptographically random session IDs (os.urandom or secrets module).",
                })

    # Session fixation: check if session ID changes after (simulated) login
    # Check if pre-auth session token persists post-login
    pre_session = None
    for c in r.cookies:
        if any(x in c.name.lower() for x in ["session", "phpsessid", "jsessionid"]):
            pre_session = c.value

    if pre_session:
        login_paths = find_login_endpoints(base)
        for path in login_paths[:1]:
            r2 = _post_form(f"{base}{path}",
                            {"username": "test@example.com", "password": "test123"},
                            headers={"Cookie": f"session={pre_session}"}, timeout=5)
            if r2:
                post_session = None
                for c in r2.cookies:
                    if any(x in c.name.lower() for x in ["session", "phpsessid"]):
                        post_session = c.value
                if post_session and post_session == pre_session:
                    findings.append({
                        "severity": "high",
                        "title": "Potential session fixation vulnerability",
                        "status": "fail",
                        "detail": "Session ID did not change after authentication attempt.",
                        "fix": "Regenerate session ID after successful login: session.regenerate() / session_regenerate_id(true).",
                    })

    if not findings:
        findings.append({
            "severity": "low",
            "title": "Session tokens appear adequately random",
            "status": "pass",
            "detail": "Session cookie values appear to be sufficiently long and non-sequential.",
        })
    return findings

# ── Default credentials ───────────────────────────────────────────────────────
def test_default_credentials(base: str) -> list:
    findings = []
    DEFAULT_CREDS = [
        ("admin",     "admin"),
        ("admin",     "password"),
        ("admin",     "123456"),
        ("admin",     "admin123"),
        ("root",      "root"),
        ("root",      "password"),
        ("test",      "test"),
        ("guest",     "guest"),
        ("admin",     ""),
        ("administrator", "administrator"),
    ]
    ADMIN_PATHS = [
        "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
        "/admin/login", "/backend", "/cms/admin",
    ]
    for path in ADMIN_PATHS[:4]:
        url = f"{base}{path}"
        r_check = _get(url, allow_redirects=True, timeout=4)
        if not r_check or r_check.status_code not in (200, 401, 403):
            continue
        for user, pwd in DEFAULT_CREDS[:5]:
            r = _post_form(url, {"username": user, "password": pwd,
                                 "user": user, "pass": pwd, "login": user}, timeout=5)
            if r and r.status_code in (200, 302):
                body = r.text.lower()
                if any(x in body for x in ["dashboard", "logout", "welcome", "admin panel",
                                            "control panel", "management"]):
                    findings.append({
                        "severity": "critical",
                        "title": f"Default credentials work: {user}:{pwd} at {path}",
                        "status": "fail",
                        "detail": f"Admin panel at {path} accepted default credentials {user}:{pwd}.",
                        "fix": "Immediately change default credentials. Enforce strong password policy. Restrict admin panel by IP.",
                    })
                    return findings
    return findings

# ── Password policy ───────────────────────────────────────────────────────────
def test_password_policy(base: str, login_paths: list) -> list:
    findings = []
    REGISTRATION_PATHS = ["/register", "/signup", "/api/register", "/api/signup", "/create-account"]
    for path in REGISTRATION_PATHS:
        r = _get(f"{base}{path}", timeout=4)
        if not r or r.status_code not in (200, 405):
            continue
        # Test weak password acceptance
        for weak_pass in ["123456", "password", "abc"]:
            r2 = _post_form(f"{base}{path}", {
                "email": "test_sec_scan@tempmail.io",
                "password": weak_pass,
                "username": "testsecuser",
            }, timeout=5)
            if r2 and r2.status_code in (200, 201):
                body = r2.text.lower()
                # If no rejection
                if not any(x in body for x in ["too weak", "too short", "minimum", "must be at least",
                                                "password requirements", "not strong"]):
                    findings.append({
                        "severity": "medium",
                        "title": f"Weak password accepted at {path}",
                        "status": "fail",
                        "detail": f"Password '{weak_pass}' was not rejected by registration endpoint.",
                        "fix": "Enforce minimum 8 chars, require mixed case + numbers. Check against HaveIBeenPwned API.",
                    })
                    return findings
        break
    return findings

# ── OAuth/SSO misconfigurations ────────────────────────────────────────────────
def test_oauth_misconfig(base: str) -> list:
    findings = []
    r = _get(base)
    if not r:
        return findings
    html = r.text.lower()

    # Check for OAuth endpoints
    oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/auth/oauth", "/.well-known/oauth-authorization-server"]
    for path in oauth_paths:
        ro = _get(f"{base}{path}", timeout=4)
        if ro and ro.status_code in (200, 302, 400):
            # Open redirect in redirect_uri
            evil_redirect = f"{base}{path}?response_type=code&client_id=test&redirect_uri=https://evil.com"
            rr = _get(evil_redirect, allow_redirects=False, timeout=5)
            if rr and rr.status_code in (301, 302):
                location = rr.headers.get("location", "")
                if "evil.com" in location:
                    findings.append({
                        "severity": "high",
                        "title": "OAuth open redirect — redirect_uri not validated",
                        "status": "fail",
                        "detail": f"OAuth endpoint redirected to evil.com. Attacker can steal auth codes.",
                        "fix": "Validate redirect_uri against a strict registered allowlist. Reject unregistered URIs.",
                    })
            break

    # Check for state parameter (CSRF protection)
    if "oauth" in html or "google-signin" in html or "facebook" in html or "github" in html:
        if "state=" not in html:
            findings.append({
                "severity": "medium",
                "title": "OAuth/SSO may lack CSRF state parameter",
                "status": "fail",
                "detail": "OAuth login buttons found but no state parameter detected in HTML. CSRF attack on OAuth flow possible.",
                "fix": "Generate and verify a cryptographically random state parameter in every OAuth flow.",
            })

    return findings

# ── Master auth scanner ────────────────────────────────────────────────────────
def scan_authentication(host: str) -> dict:
    findings = []
    score    = 100
    base     = f"https://{host}"

    login_paths = find_login_endpoints(base)

    tests = [
        ("Brute Force",         lambda: test_brute_force_protection(base, login_paths) if login_paths else []),
        ("Account Enumeration", lambda: test_account_enumeration(base, login_paths) if login_paths else []),
        ("JWT Security",        lambda: test_jwt_security(base)),
        ("Session Security",    lambda: test_session_security(base)),
        ("Default Credentials", lambda: test_default_credentials(base)),
        ("Password Policy",     lambda: test_password_policy(base, login_paths)),
        ("OAuth Misconfig",     lambda: test_oauth_misconfig(base)),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn): name for name, fn in tests}
        for future, name in futures.items():
            try:
                results = future.result(timeout=45)
                for f in results:
                    findings.append(f)
                    if f["status"] == "fail":
                        score -= {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(f["severity"], 5)
            except Exception:
                pass

    if not login_paths:
        findings.insert(0, {
            "severity": "low",
            "title": "No login endpoints found",
            "status": "info",
            "detail": "Common login paths not found — auth testing limited to JWT and session analysis.",
        })

    return {
        "id":       "auth_testing",
        "name":     "Authentication & Session",
        "icon":     "🔑",
        "score":    max(0, score),
        "findings": findings,
    }

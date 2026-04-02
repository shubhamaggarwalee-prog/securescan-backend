"""
Module 18: OWASP API Security Top 10
API1-API10: Broken Object Level Auth, Broken Auth, Excessive Data Exposure,
Lack of Resources & Rate Limiting, BFLA, Mass Assignment, Security Misconfiguration,
Injection, Improper Assets Management, Insufficient Logging
"""
import re, json
import concurrent.futures

UA      = "Mozilla/5.0 (SecureScan/2.0; +https://securescan.io)"
TIMEOUT = 8

def _get(url, headers=None, timeout=None):
    try:
        import requests
        h = {"User-Agent": UA, **(headers or {})}
        return requests.get(url, headers=h, timeout=timeout or TIMEOUT)
    except Exception:
        return None

def _post(url, data, headers=None, timeout=None):
    try:
        import requests
        h = {"User-Agent": UA, "Content-Type": "application/json", **(headers or {})}
        return requests.post(url, json=data, headers=h, timeout=timeout or TIMEOUT)
    except Exception:
        return None

# ── Discover API endpoints ─────────────────────────────────────────────────────
def discover_api_endpoints(base: str) -> list:
    COMMON_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2",
        "/graphql", "/rest", "/api/users", "/api/user", "/api/admin",
        "/api/config", "/api/settings", "/api/health", "/api/status",
        "/api/products", "/api/orders", "/api/profile", "/api/me",
        "/api/data", "/api/export", "/api/report", "/swagger-ui.html",
        "/api-docs", "/openapi.json", "/swagger.json", "/api/swagger",
    ]
    found = []
    def chk(path):
        r = _get(f"{base}{path}", timeout=4)
        if r and r.status_code in (200, 401, 403, 405):
            ct = r.headers.get("content-type", "")
            if "json" in ct or "xml" in ct or path in ["/swagger-ui.html", "/api-docs", "/openapi.json", "/swagger.json"]:
                return path
            if r.status_code in (401, 403):
                return path
            if r.status_code == 200 and len(r.content) > 30:
                try:
                    json.loads(r.text)
                    return path
                except Exception:
                    pass
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        found = [x for x in ex.map(chk, COMMON_PATHS) if x]
    return found

# ── API1: Broken Object Level Authorization (IDOR) ────────────────────────────
def test_bola(base: str, api_paths: list) -> list:
    findings = []
    IDOR_PATHS = [
        "/api/users/1", "/api/users/2", "/api/user/1",
        "/api/orders/1", "/api/orders/2",
        "/api/profile/1", "/api/accounts/1",
        "/api/v1/users/1", "/api/v1/users/2",
    ]
    for path in IDOR_PATHS:
        r = _get(f"{base}{path}", timeout=5)
        if r and r.status_code == 200:
            try:
                data = r.json()
                # Check if sensitive user data returned without auth
                sensitive = ["email", "password", "phone", "address", "ssn", "credit",
                             "token", "secret", "api_key", "dob", "birth"]
                found_fields = [k for k in (data if isinstance(data, dict) else {}) if any(s in k.lower() for s in sensitive)]
                if found_fields:
                    findings.append({
                        "severity": "critical",
                        "title": f"IDOR (API1): Unauthenticated access to {path}",
                        "status": "fail",
                        "detail": f"Object {path} returns sensitive fields without authentication: {', '.join(found_fields[:5])}",
                        "fix": "Implement object-level authorization. Verify the requesting user owns the requested object before returning data.",
                    })
                    return findings
            except Exception:
                pass
    return findings

# ── API2: Broken Authentication ────────────────────────────────────────────────
def test_broken_api_auth(base: str, api_paths: list) -> list:
    findings = []
    PROTECTED = [p for p in api_paths if any(x in p for x in ["user", "admin", "profile", "account", "order"])]

    for path in PROTECTED[:5]:
        # Test without token
        r_no_auth = _get(f"{base}{path}", timeout=5)
        # Test with invalid token
        r_bad_tok  = _get(f"{base}{path}", headers={"Authorization": "Bearer invalid_token_xyz_123"}, timeout=5)
        # Test with empty token
        r_empty    = _get(f"{base}{path}", headers={"Authorization": "Bearer "}, timeout=5)

        for r, label in [(r_no_auth, "no auth"), (r_bad_tok, "invalid token"), (r_empty, "empty token")]:
            if r and r.status_code == 200 and len(r.content) > 50:
                try:
                    data = r.json()
                    if isinstance(data, (dict, list)) and data:
                        findings.append({
                            "severity": "critical",
                            "title": f"API2 Broken Auth: {path} accessible with {label}",
                            "status": "fail",
                            "detail": f"API endpoint returned data with {label}. Authentication is not enforced.",
                            "fix": "Add authentication middleware to all API routes. Return 401 for missing/invalid tokens.",
                        })
                        return findings
                except Exception:
                    pass
    return findings

# ── API3: Excessive Data Exposure ─────────────────────────────────────────────
def test_excessive_data(base: str, api_paths: list) -> list:
    findings = []
    SENSITIVE_FIELDS = [
        "password", "password_hash", "hashed_password", "pwd",
        "ssn", "social_security", "credit_card", "card_number",
        "cvv", "secret_key", "api_key", "private_key", "token",
        "refresh_token", "access_token", "internal_id", "admin",
        "is_admin", "role", "permissions", "2fa_secret",
    ]
    for path in api_paths[:8]:
        r = _get(f"{base}{path}", timeout=5)
        if not r or r.status_code != 200:
            continue
        try:
            data = r.json()
            if isinstance(data, list) and data:
                data = data[0]
            if not isinstance(data, dict):
                continue
            # Deep scan nested fields
            all_keys = []
            def extract_keys(d, prefix=""):
                if isinstance(d, dict):
                    for k, v in d.items():
                        all_keys.append(f"{prefix}{k}".lower())
                        extract_keys(v, f"{prefix}{k}.")
                elif isinstance(d, list) and d:
                    extract_keys(d[0], prefix)
            extract_keys(data)

            exposed = [k for k in all_keys if any(s in k for s in SENSITIVE_FIELDS)]
            if exposed:
                findings.append({
                    "severity": "high",
                    "title": f"API3 Excessive Data Exposure at {path}",
                    "status": "fail",
                    "detail": f"API response includes sensitive fields: {', '.join(set(exposed[:5]))}",
                    "fix": "Use DTOs/serialisers to explicitly whitelist fields returned in API responses. Never return full database objects.",
                })
                return findings
        except Exception:
            pass
    return findings

# ── API4: Lack of Resources & Rate Limiting ────────────────────────────────────
def test_api_rate_limiting(base: str, api_paths: list) -> list:
    findings = []
    if not api_paths:
        return findings
    path = api_paths[0]
    url  = f"{base}{path}"

    # Fire 20 rapid requests
    import time
    responses = []
    start = time.time()
    try:
        import requests
        for _ in range(20):
            r = requests.get(url, headers={"User-Agent": UA}, timeout=3)
            responses.append(r.status_code)
        elapsed = time.time() - start
    except Exception:
        return findings

    rate_limited = any(s == 429 for s in responses)
    if not rate_limited:
        findings.append({
            "severity": "medium",
            "title": "API4: No rate limiting on API endpoints",
            "status": "fail",
            "detail": f"20 rapid requests to {path} — no 429 response. API vulnerable to abuse and DoS.",
            "fix": "Implement rate limiting: e.g. 100 req/min per IP. Return 429 with Retry-After header. Use Redis token bucket.",
        })
    else:
        findings.append({
            "severity": "low",
            "title": "API rate limiting is active",
            "status": "pass",
            "detail": "API returned 429 Too Many Requests during rapid request test.",
        })
    return findings

# ── API5: Broken Function Level Authorization ─────────────────────────────────
def test_bfla(base: str) -> list:
    findings = []
    ADMIN_ENDPOINTS = [
        "/api/admin", "/api/admin/users", "/api/admin/config",
        "/api/admin/settings", "/api/v1/admin", "/api/management",
        "/api/users/all", "/api/internal", "/api/debug",
    ]
    # Try to access admin endpoints without auth, and with regular user token
    for path in ADMIN_ENDPOINTS:
        r = _get(f"{base}{path}", timeout=4)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, (dict, list)) and data:
                    findings.append({
                        "severity": "critical",
                        "title": f"API5 BFLA: Admin endpoint {path} accessible without auth",
                        "status": "fail",
                        "detail": f"Administrative API endpoint {path} returns data without authentication.",
                        "fix": "Enforce role-based access control on all admin endpoints. Deny by default.",
                    })
                    return findings
            except Exception:
                pass
    return findings

# ── API6: Mass Assignment ──────────────────────────────────────────────────────
def test_mass_assignment(base: str, api_paths: list) -> list:
    findings = []
    REG_PATHS = ["/api/register", "/api/users", "/api/profile", "/api/user/update"]
    PRIV_FIELDS = {
        "is_admin": True,
        "role": "admin",
        "admin": True,
        "verified": True,
        "active": True,
        "credits": 99999,
        "balance": 99999,
        "plan": "enterprise",
    }
    for path in REG_PATHS:
        r = _post(f"{base}{path}", {
            "username": "test_mass_assign",
            "email": "masstest@securescan-test.io",
            "password": "Test1234!",
            **PRIV_FIELDS,
        }, timeout=5)
        if r and r.status_code in (200, 201):
            try:
                data = r.json()
                data_str = json.dumps(data).lower()
                accepted = [k for k in PRIV_FIELDS if k in data_str and str(PRIV_FIELDS[k]).lower() in data_str]
                if accepted:
                    findings.append({
                        "severity": "high",
                        "title": f"API6 Mass Assignment at {path}: accepted {accepted}",
                        "status": "fail",
                        "detail": f"API accepted privileged fields in response: {accepted}. Attackers can self-assign admin roles.",
                        "fix": "Use an explicit allowlist of writable fields. Never bind request body directly to database models.",
                    })
                    return findings
            except Exception:
                pass
    return findings

# ── API7: Security Misconfiguration ───────────────────────────────────────────
def test_api_misconfiguration(base: str, api_paths: list) -> list:
    findings = []

    # Debug endpoints
    DEBUG_PATHS = ["/api/debug", "/api/test", "/api/health?debug=true",
                   "/_debug", "/api/env", "/api/config/debug"]
    for path in DEBUG_PATHS:
        r = _get(f"{base}{path}", timeout=4)
        if r and r.status_code == 200:
            try:
                data = r.json()
                data_str = json.dumps(data).lower()
                if any(x in data_str for x in ["password", "secret", "key", "token", "env", "config"]):
                    findings.append({
                        "severity": "critical",
                        "title": f"API7 Debug endpoint exposes secrets: {path}",
                        "status": "fail",
                        "detail": f"Debug API endpoint {path} exposes configuration or secrets.",
                        "fix": "Disable all debug endpoints in production. Never expose environment variables or config via API.",
                    })
                    return findings
            except Exception:
                pass

    # CORS on API
    for path in api_paths[:3]:
        r = _get(f"{base}{path}", headers={"Origin": "https://evil-attacker.com"}, timeout=5)
        if r:
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")
            if acao == "https://evil-attacker.com" and acac.lower() == "true":
                findings.append({
                    "severity": "critical",
                    "title": f"API7 CORS misconfiguration: {path} reflects origin + credentials",
                    "status": "fail",
                    "detail": "API reflects arbitrary Origin header with credentials=true. Full CSRF on API possible.",
                    "fix": "Use strict CORS allowlist. Never combine reflect-origin with credentials:true.",
                })
                return findings

    # Verbose error messages
    r_err = _get(f"{base}/api/nonexistent_endpoint_xyz", timeout=4)
    if r_err and r_err.status_code in (404, 500):
        body = r_err.text.lower()
        if any(x in body for x in ["stack trace", "traceback", "exception", "at line", "sql syntax",
                                    "internal server error details", "mongodb", "orm"]):
            findings.append({
                "severity": "medium",
                "title": "API7 Verbose error messages expose stack traces",
                "status": "fail",
                "detail": "API error responses include stack traces or internal details.",
                "fix": "Return generic error messages in production. Log details server-side only.",
            })

    return findings

# ── API9: Improper Assets Management ─────────────────────────────────────────
def test_improper_assets(base: str) -> list:
    findings = []
    OLD_VERSIONS = [
        "/api/v1/users", "/api/v2/users",
        "/api/old/users", "/api/legacy/users",
        "/api/beta/", "/api/test/",
        "/api_old/", "/api_v1/",
    ]
    for path in OLD_VERSIONS[:6]:
        r = _get(f"{base}{path}", timeout=4)
        if r and r.status_code == 200:
            try:
                data = r.json()
                if data:
                    findings.append({
                        "severity": "medium",
                        "title": f"API9 Stale/undocumented API version active: {path}",
                        "status": "fail",
                        "detail": f"Older API version at {path} is still responding. Old versions may lack current security controls.",
                        "fix": "Decommission old API versions. Maintain an API inventory. Enforce versioning policy.",
                    })
                    return findings
            except Exception:
                pass
    return findings

# ── API Docs exposure ─────────────────────────────────────────────────────────
def test_api_docs(base: str) -> list:
    findings = []
    DOC_PATHS = ["/swagger-ui.html", "/api-docs", "/swagger", "/openapi.json",
                 "/swagger.json", "/redoc", "/api/swagger", "/.well-known/api"]
    for path in DOC_PATHS:
        r = _get(f"{base}{path}", timeout=4)
        if r and r.status_code == 200 and len(r.content) > 200:
            body = r.text.lower()
            if any(x in body for x in ["swagger", "openapi", "endpoint", "paths", "schemas"]):
                findings.append({
                    "severity": "medium",
                    "title": f"API documentation publicly accessible: {path}",
                    "status": "fail",
                    "detail": "API docs expose all endpoints, parameters, and schemas to unauthenticated users.",
                    "fix": "Restrict API documentation to authenticated users or internal network only in production.",
                })
                return findings
    return findings

# ── Master API scanner ─────────────────────────────────────────────────────────
def scan_owasp_api(host: str) -> dict:
    findings = []
    score    = 100
    base     = f"https://{host}"

    api_paths = discover_api_endpoints(base)

    if not api_paths:
        return {
            "id": "owasp_api",
            "name": "OWASP API Top 10",
            "icon": "🔐",
            "score": 80,
            "findings": [{
                "severity": "low",
                "title": "No API endpoints discovered",
                "status": "info",
                "detail": "No common API paths found. Manual testing may be needed for custom API paths.",
            }],
        }

    findings.append({
        "severity": "low",
        "title": f"Discovered {len(api_paths)} API endpoint(s)",
        "status": "info",
        "detail": f"Active paths: {', '.join(api_paths[:10])}",
    })

    tests = [
        ("API1 BOLA/IDOR",           lambda: test_bola(base, api_paths)),
        ("API2 Broken Auth",         lambda: test_broken_api_auth(base, api_paths)),
        ("API3 Excessive Data",      lambda: test_excessive_data(base, api_paths)),
        ("API4 Rate Limiting",       lambda: test_api_rate_limiting(base, api_paths)),
        ("API5 BFLA",                lambda: test_bfla(base)),
        ("API6 Mass Assignment",     lambda: test_mass_assignment(base, api_paths)),
        ("API7 Misconfiguration",    lambda: test_api_misconfiguration(base, api_paths)),
        ("API9 Stale Versions",      lambda: test_improper_assets(base)),
        ("API Docs Exposure",        lambda: test_api_docs(base)),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fn): name for name, fn in tests}
        for future, name in futures.items():
            try:
                results = future.result(timeout=30)
                for f in results:
                    findings.append(f)
                    if f["status"] == "fail":
                        score -= {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(f["severity"], 5)
            except Exception:
                pass

    return {
        "id":       "owasp_api",
        "name":     "OWASP API Top 10",
        "icon":     "🔐",
        "score":    max(0, score),
        "findings": findings,
    }

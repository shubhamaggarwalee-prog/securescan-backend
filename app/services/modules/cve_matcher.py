"""
Module 17: CVE Matcher
Detect software versions from headers/HTML → match against known CVE database
Uses NVD API (free, no key required for basic use)
"""
import re, json, time
import concurrent.futures

UA      = "Mozilla/5.0 (SecureScan/2.0; +https://securescan.io)"
TIMEOUT = 8

def _get(url, timeout=None):
    try:
        import requests
        return requests.get(url, headers={"User-Agent": UA}, timeout=timeout or TIMEOUT)
    except Exception:
        return None

# ── Technology fingerprinting ──────────────────────────────────────────────────
TECH_PATTERNS = [
    # (header_or_body_pattern, tech_name, version_group)
    (re.compile(r"Apache[/ ]([\d.]+)", re.I),          "Apache HTTP Server", 1),
    (re.compile(r"nginx[/ ]([\d.]+)", re.I),            "nginx",              1),
    (re.compile(r"PHP[/ ]([\d.]+)", re.I),              "PHP",                1),
    (re.compile(r"OpenSSL[/ ]([\d.]+[a-z]?)", re.I),   "OpenSSL",            1),
    (re.compile(r"WordPress[/ ]([\d.]+)", re.I),        "WordPress",          1),
    (re.compile(r"wp-includes/js/.*?ver=([\d.]+)", re.I), "WordPress",        1),
    (re.compile(r"Drupal ([\d.]+)", re.I),              "Drupal",             1),
    (re.compile(r"Joomla[!/ ]([\d.]+)", re.I),         "Joomla",             1),
    (re.compile(r"Django[/ ]([\d.]+)", re.I),           "Django",             1),
    (re.compile(r"Laravel[/ ]([\d.]+)", re.I),          "Laravel",            1),
    (re.compile(r"Rails[/ ]([\d.]+)", re.I),            "Ruby on Rails",      1),
    (re.compile(r"Express[/ ]([\d.]+)", re.I),          "Express.js",         1),
    (re.compile(r"jQuery[/ v]*([\d.]+)", re.I),         "jQuery",             1),
    (re.compile(r"Bootstrap[/ ]([\d.]+)", re.I),        "Bootstrap",          1),
    (re.compile(r"Tomcat[/ ]([\d.]+)", re.I),           "Apache Tomcat",      1),
    (re.compile(r"IIS[/ ]([\d.]+)", re.I),              "Microsoft IIS",      1),
    (re.compile(r"mod_ssl[/ ]([\d.]+)", re.I),          "mod_ssl",            1),
    (re.compile(r"Python[/ ]([\d.]+)", re.I),           "Python",             1),
    (re.compile(r"Ruby[/ ]([\d.]+)", re.I),             "Ruby",               1),
    (re.compile(r"Node[/ ]([\d.]+)", re.I),             "Node.js",            1),
    (re.compile(r"Spring[/ ]([\d.]+)", re.I),           "Spring Framework",   1),
    (re.compile(r"Struts[/ ]([\d.]+)", re.I),           "Apache Struts",      1),  # Critical CVEs
    (re.compile(r"Log4j[/ ]([\d.]+)", re.I),            "Log4j",              1),  # Log4Shell
    (re.compile(r"Shiro[/ ]([\d.]+)", re.I),            "Apache Shiro",       1),
    (re.compile(r"Jackson[/ ]([\d.]+)", re.I),          "Jackson",            1),
]

# ── Known vulnerable version ranges (offline database) ───────────────────────
# Format: (tech, min_vuln_version, max_vuln_version, cve_id, severity, description)
VULN_DB = [
    # Log4Shell — critical
    ("Log4j",              "2.0",  "2.14.1", "CVE-2021-44228", "critical", "Log4Shell: Remote Code Execution via JNDI lookup. CVSS 10.0."),
    ("Log4j",              "2.0",  "2.17.0", "CVE-2021-45046", "critical", "Log4Shell bypass. CVSS 9.0."),
    # Apache Struts
    ("Apache Struts",      "2.0",  "2.5.30", "CVE-2017-5638",  "critical", "Jakarta Multipart parser RCE. Used in Equifax breach. CVSS 10.0."),
    ("Apache Struts",      "2.0",  "2.5.33", "CVE-2023-50164", "critical", "File upload path traversal RCE. CVSS 9.8."),
    # Apache HTTP Server
    ("Apache HTTP Server", "2.4.0","2.4.49", "CVE-2021-41773", "critical", "Path traversal and RCE. CVSS 9.8."),
    ("Apache HTTP Server", "2.4.0","2.4.50", "CVE-2021-42013", "critical", "Path traversal RCE bypass. CVSS 9.8."),
    # nginx
    ("nginx",              "0.6",  "1.13.2", "CVE-2017-7529",  "medium",   "Range filter integer overflow. CVSS 7.5."),
    # PHP
    ("PHP",                "5.0",  "5.6.40", "CVE-2019-11043",  "critical", "FPM nginx RCE via newline in URL. CVSS 9.8."),
    ("PHP",                "7.0",  "7.4.25", "CVE-2021-21703",  "high",     "PHP-FPM local privilege escalation. CVSS 7.0."),
    ("PHP",                "8.0",  "8.1.1",  "CVE-2022-31625",  "critical", "PDO unserialise RCE. CVSS 9.8."),
    # WordPress
    ("WordPress",          "1.0",  "6.2.0",  "CVE-2023-2745",  "medium",   "Directory traversal via wp_lang param. CVSS 6.4."),
    ("WordPress",          "1.0",  "5.8.3",  "CVE-2022-21664",  "high",    "SQL injection in WP_Meta_Query. CVSS 7.4."),
    ("WordPress",          "1.0",  "5.7.2",  "CVE-2021-29447",  "high",    "XXE via crafted wav file upload. CVSS 7.1."),
    # Drupal
    ("Drupal",             "7.0",  "7.57",   "CVE-2018-7600",   "critical", "Drupalgeddon2: RCE via form API. CVSS 9.8."),
    ("Drupal",             "8.0",  "8.5.0",  "CVE-2018-7600",   "critical", "Drupalgeddon2: RCE. CVSS 9.8."),
    # jQuery
    ("jQuery",             "1.0",  "3.4.0",  "CVE-2019-11358",  "medium",   "Prototype pollution via $.extend. CVSS 6.1."),
    ("jQuery",             "1.0",  "3.5.0",  "CVE-2020-11022",  "medium",   "XSS via HTML parsing. CVSS 6.1."),
    # OpenSSL
    ("OpenSSL",            "1.0",  "1.0.2",  "CVE-2014-0160",   "critical", "Heartbleed: memory disclosure. CVSS 7.5."),
    ("OpenSSL",            "1.1",  "3.0.1",  "CVE-2022-0778",   "high",     "Infinite loop via BN_mod_sqrt. CVSS 7.5."),
    ("OpenSSL",            "3.0",  "3.0.6",  "CVE-2022-3786",   "critical", "X.509 email address buffer overflow. CVSS 7.5."),
    # Microsoft IIS
    ("Microsoft IIS",      "6.0",  "6.0",    "CVE-2017-7269",   "critical", "WebDAV buffer overflow RCE. CVSS 10.0."),
    ("Microsoft IIS",      "10.0", "10.0",   "CVE-2022-21907",  "critical", "HTTP protocol stack RCE. CVSS 9.8."),
    # Apache Tomcat
    ("Apache Tomcat",      "9.0",  "9.0.62", "CVE-2022-34305",  "medium",   "XSS in examples app. CVSS 6.1."),
    ("Apache Tomcat",      "8.0",  "8.5.77", "CVE-2022-29885",  "medium",   "EncryptInterceptor DoS. CVSS 7.5."),
    ("Apache Tomcat",      "10.0", "10.0.20","CVE-2022-25762",  "critical", "HTTP/2 header smuggling. CVSS 9.1."),
    # Django
    ("Django",             "2.0",  "3.2.17", "CVE-2023-23969",  "high",     "DoS via Accept-Language header. CVSS 7.5."),
    ("Django",             "3.0",  "4.1.6",  "CVE-2023-24580",  "high",     "DoS via multipart/form-data. CVSS 7.5."),
    # Spring
    ("Spring Framework",   "5.0",  "5.3.17", "CVE-2022-22965",  "critical", "Spring4Shell: RCE via DataBinder. CVSS 9.8."),
    ("Spring Framework",   "5.0",  "5.3.24", "CVE-2022-31692",  "high",     "Authorization bypass. CVSS 9.8."),
    # Ruby on Rails
    ("Ruby on Rails",      "6.0",  "7.0.4",  "CVE-2022-32224",  "critical", "ReDoS + potential RCE via YAML. CVSS 9.8."),
    # Apache Shiro
    ("Apache Shiro",       "1.0",  "1.9.0",  "CVE-2022-32532",  "critical", "Authentication bypass via RegExPatternMatcher. CVSS 9.8."),
]

def parse_version(v: str):
    """Parse version string to tuple for comparison."""
    try:
        parts = re.findall(r"\d+", str(v))
        return tuple(int(x) for x in parts[:4])
    except Exception:
        return (0,)

def version_lte(v1: str, v2: str) -> bool:
    return parse_version(v1) <= parse_version(v2)

def version_gte(v1: str, v2: str) -> bool:
    return parse_version(v1) >= parse_version(v2)

def check_cves(tech: str, version: str) -> list:
    results = []
    for (t, min_v, max_v, cve, sev, desc) in VULN_DB:
        if t.lower() != tech.lower():
            continue
        if version_gte(version, min_v) and version_lte(version, max_v):
            results.append({
                "severity": sev,
                "title":    f"{cve} — {tech} {version}",
                "status":   "fail",
                "detail":   desc,
                "fix":      f"Upgrade {tech} to the latest stable version immediately. See https://nvd.nist.gov/vuln/detail/{cve}",
                "cve":      cve,
            })
    return results

# ── Fetch CVE details from NVD API ────────────────────────────────────────────
def fetch_nvd_cve(cve_id: str) -> dict | None:
    try:
        import requests
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            headers={"User-Agent": UA},
            timeout=6,
        )
        if r.status_code == 200:
            data = r.json()
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            metrics = vuln.get("metrics", {})
            cvss = None
            for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if k in metrics:
                    cvss = metrics[k][0].get("cvssData", {}).get("baseScore")
                    break
            desc = vuln.get("descriptions", [{}])[0].get("value", "")
            return {"cvss": cvss, "description": desc[:200]}
    except Exception:
        pass
    return None

# ── Detect technologies from response ─────────────────────────────────────────
def detect_technologies(host: str) -> dict:
    """Returns {tech_name: version} dict"""
    detected = {}
    r = _get(f"https://{host}")
    if not r:
        return detected

    # Search in headers + body
    searchable = str(r.headers) + " " + r.text[:10000]

    for pattern, tech, group in TECH_PATTERNS:
        m = pattern.search(searchable)
        if m:
            version = m.group(group) if group <= len(m.groups()) else "unknown"
            if tech not in detected:
                detected[tech] = version

    # Also check common JS version files
    for path, tech in [("/wp-includes/version.php", "WordPress"), ("/changelog.txt", "Drupal")]:
        rv = _get(f"https://{host}{path}", timeout=4)
        if rv and rv.status_code == 200:
            for pattern, t, g in TECH_PATTERNS:
                if t == tech:
                    m = pattern.search(rv.text)
                    if m:
                        detected[tech] = m.group(g)

    return detected

# ── Master CVE scanner ─────────────────────────────────────────────────────────
def scan_cve(host: str) -> dict:
    findings = []
    score    = 100

    detected = detect_technologies(host)

    if not detected:
        findings.append({
            "severity": "low",
            "title": "No versioned technologies detected",
            "status": "info",
            "detail": "Could not fingerprint software versions. Server may be hiding version information (good practice).",
        })
        return {"id": "cve", "name": "CVE / Known Vulnerabilities", "icon": "🔍", "score": 100, "findings": findings}

    # Record what we found
    for tech, version in detected.items():
        findings.append({
            "severity": "low" if version != "unknown" else "medium",
            "title": f"Detected: {tech} {version}",
            "status": "info",
            "detail": f"Technology fingerprint found: {tech} version {version}",
        })

    # Check each against vuln DB
    cve_findings = []
    for tech, version in detected.items():
        if version == "unknown":
            continue
        vulns = check_cves(tech, version)
        for v in vulns:
            cve_findings.append(v)
            score -= {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(v["severity"], 5)

    # Try to enrich top critical CVEs with NVD data
    critical_cves = [f for f in cve_findings if f["severity"] == "critical"][:3]
    for finding in critical_cves:
        cve_id = finding.get("cve")
        if cve_id:
            nvd = fetch_nvd_cve(cve_id)
            if nvd and nvd.get("cvss"):
                finding["detail"] += f" CVSS: {nvd['cvss']}"

    findings.extend(cve_findings)

    if not cve_findings:
        findings.append({
            "severity": "low",
            "title": "No known CVEs found for detected versions",
            "status": "pass",
            "detail": f"Checked {len(detected)} detected technologies against CVE database. No matches.",
        })

    return {
        "id":       "cve",
        "name":     "CVE / Known Vulnerabilities",
        "icon":     "🔍",
        "score":    max(0, score),
        "findings": findings,
    }

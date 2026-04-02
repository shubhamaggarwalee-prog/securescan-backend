"""
SecureScan Engine — 14 modules, 100+ checks
All checks run concurrently using ThreadPoolExecutor
"""
import ssl, socket, re, concurrent.futures, time
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver, dns.zone, dns.query, dns.reversename
    DNS_OK = True
except ImportError:
    DNS_OK = False

UA      = "Mozilla/5.0 (SecureScan/2.0; +https://securescan.io)"
TIMEOUT = 8

def _get(url, method="GET", headers=None, allow_redirects=True, data=None, timeout=None):
    if not REQUESTS_OK:
        return None
    try:
        h = {"User-Agent": UA, **(headers or {})}
        t = timeout or TIMEOUT
        if method == "POST":
            return requests.post(url, headers=h, timeout=t, json=data, allow_redirects=allow_redirects)
        return requests.get(url, headers=h, timeout=t, allow_redirects=allow_redirects)
    except Exception:
        return None

# ── 1. SSL / TLS ──────────────────────────────────────────────────────────────
def scan_ssl(host):
    findings, score = [], 100
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert  = tls.getpeercert()
                proto = tls.version()
        exp = cert.get("notAfter","")
        if exp:
            expire = datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days   = (expire - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append({"severity":"critical","title":"Certificate EXPIRED","status":"fail","detail":f"Expired {abs(days)} days ago.","fix":"Renew SSL certificate immediately. Use Let's Encrypt for free certs."})
                score -= 40
            elif days < 14:
                findings.append({"severity":"high","title":f"Certificate expires in {days} days","status":"fail","detail":"Imminent expiry — browsers will show warnings.","fix":"Renew SSL certificate immediately."})
                score -= 25
            elif days < 30:
                findings.append({"severity":"medium","title":f"Certificate expires in {days} days","status":"fail","detail":"Renewal recommended soon.","fix":"Schedule certificate renewal."})
                score -= 10
            else:
                findings.append({"severity":"low","title":f"Certificate valid — {days} days remaining","status":"pass","detail":"No expiry action needed."})
        if proto in ("TLSv1","TLSv1.1"):
            findings.append({"severity":"high","title":f"Outdated protocol: {proto}","status":"fail","detail":"TLS 1.0/1.1 are deprecated and vulnerable.","fix":"Configure server: TLS 1.2 minimum, prefer TLS 1.3."})
            score -= 20
        else:
            findings.append({"severity":"low","title":f"Protocol: {proto}","status":"pass","detail":"Modern TLS version in use."})
        findings.append({"severity":"low","title":"Certificate trusted by CA","status":"pass","detail":"Certificate validates against system trust store."})
    except ssl.SSLCertVerificationError:
        findings.append({"severity":"critical","title":"Certificate not trusted / self-signed","status":"fail","detail":"Browsers will block users with security warnings.","fix":"Use a CA-signed certificate. Let's Encrypt is free."})
        score -= 40
    except ConnectionRefusedError:
        findings.append({"severity":"critical","title":"HTTPS not available (port 443 refused)","status":"fail","detail":"Server not accepting HTTPS connections.","fix":"Enable HTTPS on your server."})
        score -= 50
    except Exception as e:
        findings.append({"severity":"high","title":"SSL connection failed","status":"fail","detail":str(e),"fix":"Ensure HTTPS is enabled and port 443 is open."})
        score -= 30
    return {"id":"ssl","name":"SSL / TLS","icon":"🔒","score":max(0,score),"findings":findings}

# ── 2. TLS Deep Scan ──────────────────────────────────────────────────────────
def scan_tls_deep(host):
    findings, score = [], 100
    WEAK = ["RC4","DES","3DES","NULL","EXPORT","ADH","AECDH"]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cipher_name, _, bits = tls.cipher()
                cert = tls.getpeercert()
        w = [x for x in WEAK if x in cipher_name.upper()]
        if w:
            findings.append({"severity":"high","title":f"Weak cipher: {cipher_name}","status":"fail","detail":f"Contains: {', '.join(w)}","fix":"Configure server to prefer ECDHE+AES256-GCM. Remove RC4, DES, 3DES."})
            score -= 25
        else:
            findings.append({"severity":"low","title":f"Cipher: {cipher_name} ({bits}-bit)","status":"pass","detail":"Strong cipher suite in use."})
        if bits and bits < 128:
            findings.append({"severity":"critical","title":f"Weak key size: {bits} bits","status":"fail","detail":"Key size below 128 bits is cryptographically broken.","fix":"Use 2048-bit RSA or 256-bit ECDSA minimum."})
            score -= 30
        issuer  = dict(x[0] for x in cert.get("issuer",[]))
        subject = dict(x[0] for x in cert.get("subject",[]))
        if issuer == subject:
            findings.append({"severity":"critical","title":"Self-signed certificate","status":"fail","detail":"Not issued by a trusted CA.","fix":"Use Let's Encrypt or another trusted CA."})
            score -= 40
        else:
            findings.append({"severity":"low","title":f"Issued by: {issuer.get('organizationName','CA')}","status":"pass","detail":"Trusted CA-signed certificate."})
        # SHA-1
        sig = cert.get("signatureAlgorithm","")
        if "sha1" in str(sig).lower():
            findings.append({"severity":"high","title":"SHA-1 signature algorithm","status":"fail","detail":"SHA-1 is cryptographically broken.","fix":"Reissue certificate with SHA-256 or better."})
            score -= 20
        else:
            findings.append({"severity":"low","title":"Strong signature algorithm","status":"pass","detail":"SHA-256 or better in use."})
    except Exception as e:
        findings.append({"severity":"medium","title":"TLS deep scan error","status":"warn","detail":str(e)})

    r = _get(f"https://{host}")
    if r:
        hsts = r.headers.get("strict-transport-security","")
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts)
            ma = int(m.group(1)) if m else 0
            if ma < 31536000:
                findings.append({"severity":"medium","title":f"HSTS max-age too short ({ma}s)","status":"fail","detail":"Should be at least 1 year.","fix":"Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"})
                score -= 10
            else:
                findings.append({"severity":"low","title":f"HSTS max-age: {ma}s","status":"pass","detail":"Adequate HSTS max-age."})
            if "includeSubDomains" not in hsts:
                findings.append({"severity":"medium","title":"HSTS missing includeSubDomains","status":"fail","detail":"Subdomains not protected by HSTS.","fix":"Add includeSubDomains to HSTS header."})
                score -= 8
            if "preload" in hsts:
                findings.append({"severity":"low","title":"HSTS preload enabled","status":"pass","detail":"Site is eligible for HSTS preload list."})
        else:
            findings.append({"severity":"high","title":"No HSTS header","status":"fail","detail":"Strict-Transport-Security not set.","fix":"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"})
            score -= 15
    return {"id":"tls_deep","name":"TLS Deep Scan","icon":"🛡️","score":max(0,score),"findings":findings}

# ── 3. Security Headers ───────────────────────────────────────────────────────
def scan_headers(host):
    findings, score = [], 100
    r = _get(f"https://{host}")
    if not r:
        return {"id":"headers","name":"Security Headers","icon":"🛡️","score":50,"findings":[{"severity":"medium","title":"Could not fetch headers","status":"error","detail":"Site unreachable."}]}
    h = {k.lower(): v for k, v in r.headers.items()}
    CHECKS = [
        ("content-security-policy",   "high",   "Content-Security-Policy",   "Add: Content-Security-Policy: default-src 'self'"),
        ("strict-transport-security", "high",   "Strict-Transport-Security", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("x-frame-options",           "medium", "X-Frame-Options",           "Add: X-Frame-Options: DENY"),
        ("x-content-type-options",    "medium", "X-Content-Type-Options",    "Add: X-Content-Type-Options: nosniff"),
        ("referrer-policy",           "low",    "Referrer-Policy",           "Add: Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy",        "low",    "Permissions-Policy",        "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
        ("cross-origin-opener-policy","low",    "Cross-Origin-Opener-Policy","Add: Cross-Origin-Opener-Policy: same-origin"),
        ("cross-origin-resource-policy","low",  "Cross-Origin-Resource-Policy","Add: Cross-Origin-Resource-Policy: same-origin"),
    ]
    for hdr, sev, label, fix in CHECKS:
        if hdr in h:
            findings.append({"severity":"low","title":f"{label} present","status":"pass","detail":h[hdr][:120]})
        else:
            findings.append({"severity":sev,"title":f"Missing: {label}","status":"fail","detail":f"{label} header is not set.","fix":fix})
            score -= {"high":20,"medium":10,"low":5}[sev]
    # HTTP→HTTPS redirect
    rh = _get(f"http://{host}", allow_redirects=False)
    if rh and rh.status_code in (301,302,307,308) and "https" in rh.headers.get("location","").lower():
        findings.append({"severity":"low","title":"HTTP redirects to HTTPS","status":"pass","detail":"301/302 redirect in place."})
    else:
        findings.append({"severity":"high","title":"No HTTP → HTTPS redirect","status":"fail","detail":"Plain HTTP not forced to HTTPS.","fix":"Add 301 redirect from http:// to https://."})
        score -= 15
    return {"id":"headers","name":"Security Headers","icon":"🛡️","score":max(0,score),"findings":findings}

# ── 4. Content Security ───────────────────────────────────────────────────────
def scan_content(host):
    findings, score = [], 100
    r = _get(f"https://{host}")
    if not r:
        return {"id":"content","name":"Content Security","icon":"🔐","score":50,"findings":[]}
    h   = {k.lower(): v for k, v in r.headers.items()}
    csp = h.get("content-security-policy","")
    if csp:
        if "'unsafe-inline'" in csp:
            findings.append({"severity":"high","title":"CSP allows 'unsafe-inline'","status":"fail","detail":"Inline scripts/styles permitted — XSS mitigation bypassed.","fix":"Remove 'unsafe-inline'. Use nonces: script-src 'nonce-{random}'"})
            score -= 20
        if "'unsafe-eval'" in csp:
            findings.append({"severity":"high","title":"CSP allows 'unsafe-eval'","status":"fail","detail":"eval() is permitted — eval-based XSS possible.","fix":"Remove 'unsafe-eval'. Refactor code that uses eval."})
            score -= 15
        if re.search(r"(src|uri)\s+[^;]*\*", csp, re.I):
            findings.append({"severity":"medium","title":"CSP contains wildcard sources","status":"fail","detail":"Wildcard (*) allows loading from any host.","fix":"Replace wildcards with explicit trusted domains."})
            score -= 10
        if "object-src" not in csp:
            findings.append({"severity":"medium","title":"CSP missing object-src directive","status":"fail","detail":"Plugin content (Flash, Java) not restricted.","fix":"Add: object-src 'none'"})
            score -= 8
        if "base-uri" not in csp:
            findings.append({"severity":"low","title":"CSP missing base-uri directive","status":"fail","detail":"Base element can be hijacked.","fix":"Add: base-uri 'self'"})
            score -= 5
        findings.append({"severity":"low","title":"CSP header is present","status":"pass","detail":"Content-Security-Policy configured."})
    else:
        findings.append({"severity":"high","title":"No Content-Security-Policy","status":"fail","detail":"No CSP — XSS has no policy barrier.","fix":"Add: Content-Security-Policy: default-src 'self'; object-src 'none'"})
        score -= 25
    # SRI on CDN scripts
    cdn_scripts = re.findall(r'<script[^>]+src=["\']https?://(?!'+re.escape(host)+r')[^"\']+["\'][^>]*>', r.text, re.I)
    sri_missing = [s for s in cdn_scripts if "integrity=" not in s.lower()]
    if sri_missing:
        findings.append({"severity":"medium","title":f"{len(sri_missing)} CDN script(s) missing SRI","status":"fail","detail":"External scripts loaded without integrity verification.","fix":"Add integrity attribute: integrity='sha384-...' crossorigin='anonymous'"})
        score -= 10
    elif cdn_scripts:
        findings.append({"severity":"low","title":"CDN scripts have SRI integrity checks","status":"pass","detail":"External scripts are integrity-verified."})
    # Mixed content
    if re.search(r'(src|href)=["\']http://[^"\']+["\']', r.text, re.I):
        findings.append({"severity":"high","title":"Mixed content detected","status":"fail","detail":"HTTP resources on HTTPS page degrade security.","fix":"Change all resource URLs from http:// to https://."})
        score -= 20
    else:
        findings.append({"severity":"low","title":"No mixed content","status":"pass","detail":"All detected resources use HTTPS."})
    return {"id":"content","name":"Content Security","icon":"🔐","score":max(0,score),"findings":findings}

# ── 5. DNS & Email ────────────────────────────────────────────────────────────
def scan_dns(host):
    findings, score = [], 100
    if not DNS_OK:
        return {"id":"dns","name":"DNS & Email","icon":"🌐","score":50,"findings":[{"severity":"medium","title":"dnspython not installed","status":"error","detail":"pip install dnspython"}]}
    domain = ".".join(host.split(".")[-2:])
    # SPF
    try:
        txts = dns.resolver.resolve(domain, "TXT")
        spf  = [str(r) for r in txts if "v=spf1" in str(r)]
        if spf:
            if "+all" in spf[0]:
                findings.append({"severity":"high","title":"SPF uses +all (any server can send)","status":"fail","detail":"Completely defeats SPF protection.","fix":"Replace +all with ~all or -all."})
                score -= 20
            else:
                findings.append({"severity":"low","title":"SPF record configured","status":"pass","detail":spf[0][:80]})
        else:
            findings.append({"severity":"high","title":"No SPF record","status":"fail","detail":"Email spoofing is trivially possible.","fix":f"Add TXT: v=spf1 include:_spf.google.com ~all"})
            score -= 20
    except Exception:
        findings.append({"severity":"high","title":"SPF lookup failed","status":"fail","detail":"No TXT records reachable.","fix":"Add SPF TXT record to your DNS zone."})
        score -= 15
    # DMARC
    try:
        dm  = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        ds  = str(list(dm)[0])
        if "p=none" in ds:
            findings.append({"severity":"medium","title":"DMARC policy p=none (monitoring only)","status":"fail","detail":"Spoofed emails not rejected, just reported.","fix":"Change to p=quarantine or p=reject."})
            score -= 10
        else:
            findings.append({"severity":"low","title":"DMARC configured with enforcement","status":"pass","detail":ds[:80]})
    except Exception:
        findings.append({"severity":"high","title":"No DMARC record","status":"fail","detail":"Email spoofing not blocked.","fix":f"Add TXT at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"})
        score -= 20
    # DKIM (common selectors)
    dkim_found = False
    for sel in ["default","google","mail","smtp","dkim","k1","selector1","selector2"]:
        try:
            dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            findings.append({"severity":"low","title":f"DKIM configured (selector: {sel})","status":"pass","detail":"Email signing is enabled."})
            dkim_found = True
            break
        except Exception:
            pass
    if not dkim_found:
        findings.append({"severity":"medium","title":"No DKIM record found","status":"fail","detail":"Email integrity signing not detected.","fix":"Configure DKIM via your email provider."})
        score -= 10
    # DNSSEC
    try:
        dns.resolver.resolve(domain, "DNSKEY")
        findings.append({"severity":"low","title":"DNSSEC enabled","status":"pass","detail":"DNS records are cryptographically signed."})
    except Exception:
        findings.append({"severity":"low","title":"DNSSEC not enabled","status":"fail","detail":"DNS records can be spoofed.","fix":"Enable DNSSEC through your domain registrar."})
        score -= 5
    return {"id":"dns","name":"DNS & Email","icon":"🌐","score":max(0,score),"findings":findings}

# ── 6. DNS Advanced ───────────────────────────────────────────────────────────
def scan_dns_advanced(host):
    findings, score = [], 100
    if not DNS_OK:
        return {"id":"dns_adv","name":"DNS Advanced","icon":"🗺️","score":50,"findings":[]}
    domain = ".".join(host.split(".")[-2:])
    # CAA
    try:
        dns.resolver.resolve(domain, "CAA")
        findings.append({"severity":"low","title":"CAA records configured","status":"pass","detail":"Only authorised CAs can issue certs."})
    except Exception:
        findings.append({"severity":"medium","title":"No CAA records","status":"fail","detail":"Any CA can issue certificates for your domain.","fix":f'Add: {domain}. CAA 0 issue "letsencrypt.org"'})
        score -= 10
    # Zone transfer
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        xfr_allowed = False
        for ns in list(ns_records)[:2]:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns.target).rstrip("."), domain, timeout=3))
                if zone:
                    findings.append({"severity":"critical","title":f"Zone transfer allowed: {ns.target}","status":"fail","detail":"Full DNS zone exposed to anyone.","fix":"Disable AXFR on all nameservers."})
                    score -= 35; xfr_allowed = True; break
            except Exception:
                pass
        if not xfr_allowed:
            findings.append({"severity":"low","title":"Zone transfer disabled","status":"pass","detail":"Nameservers reject AXFR requests."})
    except Exception:
        pass
    # Subdomain enumeration
    SUBS = ["www","api","dev","staging","admin","mail","ftp","test","beta","cdn","app",
            "dashboard","portal","vpn","remote","gitlab","jenkins","grafana","kibana"]
    def chk(sub):
        try:
            dns.resolver.resolve(f"{sub}.{domain}", "A")
            return sub
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        found = [x for x in ex.map(chk, SUBS) if x]
    if found:
        findings.append({"severity":"low","title":f"{len(found)} subdomains discovered","status":"info","detail":"Active: "+", ".join(found)})
    # Subdomain takeover check (common CNAME patterns)
    TAKEOVER_SIGS = {
        "github.io": "GitHub Pages","s3.amazonaws.com": "AWS S3",
        "herokuapp.com": "Heroku","netlify.app": "Netlify",
        "azurewebsites.net": "Azure","fastly.net": "Fastly",
    }
    for sub in found:
        try:
            cnames = dns.resolver.resolve(f"{sub}.{domain}", "CNAME")
            for cname in cnames:
                target = str(cname.target).lower()
                for sig, provider in TAKEOVER_SIGS.items():
                    if sig in target:
                        r = _get(f"https://{sub}.{domain}", timeout=4)
                        if r and (r.status_code == 404 or "there isn't a github pages" in r.text.lower()):
                            findings.append({"severity":"critical","title":f"Subdomain takeover: {sub}.{domain}","status":"fail","detail":f"Points to unclaimed {provider} resource.","fix":f"Either claim the {provider} resource or remove the DNS record."})
                            score -= 30
        except Exception:
            pass
    return {"id":"dns_adv","name":"DNS Advanced","icon":"🗺️","score":max(0,score),"findings":findings}

# ── 7. Cookies ────────────────────────────────────────────────────────────────
def scan_cookies(host):
    findings, score = [], 100
    r = _get(f"https://{host}")
    if not r:
        return {"id":"cookies","name":"Cookies","icon":"🍪","score":50,"findings":[{"severity":"medium","title":"Could not reach site","status":"error","detail":""}]}
    if not r.cookies:
        findings.append({"severity":"low","title":"No cookies set on homepage","status":"pass","detail":"No Set-Cookie headers on this page."})
        return {"id":"cookies","name":"Cookies","icon":"🍪","score":100,"findings":findings}
    for c in r.cookies:
        nm = c.name
        if not c.secure:
            findings.append({"severity":"high","title":f"Cookie '{nm}' missing Secure flag","status":"fail","detail":"Cookie sent over plain HTTP.","fix":f"Add Secure flag to '{nm}'."})
            score -= 15
        if not c.has_nonstandard_attr("HttpOnly"):
            findings.append({"severity":"high","title":f"Cookie '{nm}' missing HttpOnly","status":"fail","detail":"JavaScript can read this cookie — XSS can steal sessions.","fix":f"Add HttpOnly flag to '{nm}'."})
            score -= 15
        if not c.has_nonstandard_attr("SameSite"):
            findings.append({"severity":"medium","title":f"Cookie '{nm}' missing SameSite","status":"fail","detail":"CSRF risk without SameSite attribute.","fix":f"Add SameSite=Strict or Lax to '{nm}'."})
            score -= 8
        else:
            findings.append({"severity":"low","title":f"Cookie '{nm}' flags OK","status":"pass","detail":"Secure, HttpOnly, SameSite all set."})
    return {"id":"cookies","name":"Cookies","icon":"🍪","score":max(0,score),"findings":findings}

# ── 8. Information Leakage ────────────────────────────────────────────────────
def scan_info(host):
    findings, score = [], 100
    r = _get(f"https://{host}")
    if not r:
        return {"id":"info","name":"Information Leakage","icon":"📄","score":50,"findings":[]}
    h = {k.lower(): v for k, v in r.headers.items()}
    LEAKY = ["server","x-powered-by","x-aspnet-version","x-aspnetmvc-version","x-generator","x-drupal-cache","x-wp-total"]
    for hdr in LEAKY:
        val = h.get(hdr,"")
        if val and re.search(r"[\d.]{3,}", val):
            findings.append({"severity":"medium","title":f"Version in {hdr}: {val}","status":"fail","detail":"Exact version enables targeted CVE attacks.","fix":f"Remove or genericise the {hdr} header."})
            score -= 10
        elif val:
            findings.append({"severity":"low","title":f"{hdr}: {val} (no version)","status":"pass","detail":"Tech visible but no version number."})
    # Generator meta tag
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', r.text, re.I)
    if gen:
        findings.append({"severity":"low","title":f"Generator meta: {gen.group(1)}","status":"fail","detail":"CMS/framework version visible in HTML.","fix":"Remove the generator meta tag."})
        score -= 5
    if score == 100:
        findings.append({"severity":"low","title":"No version disclosure detected","status":"pass","detail":"No version information found in headers."})
    return {"id":"info","name":"Information Leakage","icon":"📄","score":max(0,score),"findings":findings}

# ── 9. Sensitive Files (45 paths) ─────────────────────────────────────────────
def scan_files(host):
    findings, score = [], 100
    base = f"https://{host}"
    PATHS = [
        ("/.env","critical",".env file","Remove from webroot. Add to .gitignore. Rotate all exposed secrets."),
        ("/.env.local","critical",".env.local","Remove all .env* files from public directories."),
        ("/.env.production","critical",".env.production","Remove all .env* files from public directories."),
        ("/.env.backup","critical",".env.backup","Remove backup env files from webroot."),
        ("/.git/HEAD","critical","Git repo exposed","Add to nginx: location /.git { deny all; return 404; }"),
        ("/.git/config","critical","Git config","Block all /.git/ access immediately."),
        ("/.git/COMMIT_EDITMSG","critical","Git commit history","Block /.git/ directory."),
        ("/wp-config.php","critical","wp-config.php","Add to .htaccess: <Files wp-config.php> deny from all </Files>"),
        ("/wp-config.php.bak","critical","wp-config.php backup","Remove backup config files."),
        ("/backup.zip","critical","backup.zip","Remove backups from webroot."),
        ("/backup.tar.gz","critical","backup.tar.gz","Remove backup archives from webroot."),
        ("/backup.sql","critical","SQL backup","Move DB backups outside webroot."),
        ("/db.sql","critical","db.sql dump","Remove SQL dumps immediately."),
        ("/dump.sql","critical","dump.sql","Remove SQL dumps immediately."),
        ("/database.sql","critical","database.sql","Remove SQL dumps immediately."),
        ("/phpmyadmin/","high","phpMyAdmin","Remove or restrict to specific IPs."),
        ("/pma/","high","phpMyAdmin (pma)","Remove or IP-restrict phpMyAdmin."),
        ("/adminer.php","high","Adminer DB tool","Remove Adminer from production."),
        ("/web.config","high","web.config","Restrict via IIS config."),
        ("/config.php","high","config.php","Move config files outside webroot."),
        ("/docker-compose.yml","high","docker-compose.yml","Remove from webroot."),
        ("/docker-compose.yaml","high","docker-compose.yaml","Remove from webroot."),
        ("/Dockerfile","high","Dockerfile","Remove from webroot."),
        ("/error.log","high","error.log","Move log files outside webroot."),
        ("/access.log","high","access.log","Move log files outside webroot."),
        ("/laravel.log","high","Laravel log","Move storage/ outside webroot."),
        ("/.htpasswd","high",".htpasswd","Restrict .htpasswd: location /.htpasswd { deny all; }"),
        ("/settings.py","high","Django settings","Move settings outside webroot."),
        ("/database.yml","high","Rails database.yml","Move config/ outside webroot."),
        ("/server-status","medium","Apache server-status","Restrict to localhost: Allow from 127.0.0.1"),
        ("/server-info","medium","Apache server-info","Restrict to localhost."),
        ("/composer.json","medium","composer.json","Block: location ~ composer\\.json { deny all; }"),
        ("/composer.lock","medium","composer.lock","Block composer files."),
        ("/package.json","low","package.json","Block from public access."),
        ("/yarn.lock","low","yarn.lock","Block lockfiles from public access."),
        ("/swagger.json","medium","swagger.json","Restrict Swagger to authenticated users."),
        ("/openapi.json","medium","openapi.json","Restrict API spec to authenticated users."),
        ("/api/swagger","medium","API Swagger UI","Restrict Swagger UI in production."),
        ("/phpinfo.php","critical","phpinfo()","Remove phpinfo.php immediately."),
        ("/info.php","critical","phpinfo (info.php)","Remove phpinfo.php files."),
        ("/.DS_Store","low",".DS_Store (macOS)","Add to .gitignore: .DS_Store"),
        ("/Thumbs.db","low","Thumbs.db (Windows)","Add to .gitignore: Thumbs.db"),
        ("/Jenkinsfile","medium","Jenkinsfile","Remove CI/CD config from webroot."),
        ("/.travis.yml","low",".travis.yml","Remove CI config from webroot."),
        ("/.well-known/security.txt","low","security.txt ✓ (good)",None),
    ]
    found = 0
    lock = concurrent.futures.ThreadPoolExecutor(max_workers=12)
    results = []
    def chk(args):
        path, sev, label, fix = args
        r = _get(f"{base}{path}", allow_redirects=False, timeout=5)
        if r and r.status_code == 200 and len(r.content) > 8:
            return (path, sev, label, fix, len(r.content))
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(chk, PATHS):
            if res:
                path, sev, label, fix, size = res
                found += 1
                score -= {"critical":30,"high":20,"medium":10,"low":0}[sev]
                if fix:
                    findings.append({"severity":sev,"title":f"EXPOSED: {label}","status":"fail","detail":f"{path} returned HTTP 200 ({size} bytes).","fix":fix})
                else:
                    findings.append({"severity":sev,"title":label,"status":"pass","detail":f"{path} is publicly accessible."})
    if found == 0:
        findings.append({"severity":"low","title":f"No sensitive files exposed","status":"pass","detail":f"Checked {len(PATHS)} paths — none returned HTTP 200."})
    return {"id":"files","name":"Sensitive Files","icon":"📁","score":max(0,score),"findings":findings}

# ── 10. Open Ports ────────────────────────────────────────────────────────────
def scan_ports(host):
    findings, score = [], 100
    PORTS = [
        (21,   "FTP",           "high",    "Disable FTP. Use SFTP/SCP instead."),
        (22,   "SSH",           "medium",  "Restrict SSH to key auth only. Use fail2ban."),
        (23,   "Telnet",        "critical","Disable Telnet. Use SSH."),
        (25,   "SMTP",          "medium",  "Verify not an open relay."),
        (110,  "POP3",          "medium",  "Use encrypted POP3S on port 995."),
        (143,  "IMAP",          "medium",  "Use encrypted IMAPS on port 993."),
        (3306, "MySQL",         "critical","Firewall MySQL — never expose to internet."),
        (5432, "PostgreSQL",    "critical","Firewall PostgreSQL — databases must not be public."),
        (6379, "Redis",         "critical","Firewall Redis — default config has no auth."),
        (27017,"MongoDB",       "critical","Firewall MongoDB — default allows unauthenticated access."),
        (8080, "HTTP-alt",      "medium",  "Close 8080 or restrict by IP."),
        (8443, "HTTPS-alt",     "low",     "Verify 8443 is intentional."),
        (9200, "Elasticsearch", "critical","Firewall Elasticsearch — full data readable without auth."),
    ]
    def chk(args):
        port, name, sev, fix = args
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return (port, name, sev, fix, True)
        except Exception:
            return (port, name, sev, fix, False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=13) as ex:
        for port, name, sev, fix, open_ in ex.map(chk, PORTS):
            if open_:
                score -= {"critical":30,"high":20,"medium":10,"low":5}[sev]
                findings.append({"severity":sev,"title":f"Port {port} ({name}) open","status":"fail","detail":f"Port {port} reachable from internet.","fix":fix})
    if not findings:
        findings.append({"severity":"low","title":"No dangerous ports open","status":"pass","detail":f"Checked {len(PORTS)} high-risk ports — none open."})
    return {"id":"ports","name":"Open Ports","icon":"🚪","score":max(0,score),"findings":findings}

# ── 11. CORS Policy ───────────────────────────────────────────────────────────
def scan_cors(host):
    findings, score = [], 100
    base = f"https://{host}"
    wild = reflect = null_ = cred = False
    for origin in ["https://evil-attacker.com", "null", f"https://evil.{host}"]:
        r = _get(base, headers={"Origin": origin})
        if not r: continue
        acao = r.headers.get("access-control-allow-origin","")
        acac = r.headers.get("access-control-allow-credentials","")
        if acao == "*" and not wild:
            findings.append({"severity":"medium","title":"CORS wildcard (*) allowed","status":"fail","detail":"Any site can make cross-origin requests.","fix":"Replace * with explicit origin allowlist."})
            score -= 15; wild = True
        elif acao == origin and origin != "null" and not reflect:
            findings.append({"severity":"high","title":"CORS reflects arbitrary Origin","status":"fail","detail":"Server mirrors attacker-supplied Origin.","fix":"Validate Origin against a strict allowlist. Never reflect blindly."})
            score -= 25; reflect = True
            if acac.lower() == "true" and not cred:
                findings.append({"severity":"critical","title":"CORS: reflected origin + credentials","status":"fail","detail":"Attackers can make authenticated requests cross-origin.","fix":"Never use credentials:true with reflected/wildcard origins."})
                score -= 25; cred = True
        elif acao == "null" and origin == "null" and not null_:
            findings.append({"severity":"high","title":"CORS allows null origin","status":"fail","detail":"Sandboxed iframes accepted as origin.","fix":"Remove null from CORS allowlist."})
            score -= 20; null_ = True
    # API paths
    for path in ["/api", "/api/v1", "/graphql"]:
        ra = _get(f"{base}{path}", headers={"Origin":"https://evil.com"}, timeout=4)
        if ra:
            acao = ra.headers.get("access-control-allow-origin","")
            if acao in ("*", "https://evil.com"):
                findings.append({"severity":"high","title":f"CORS misconfigured on {path}","status":"fail","detail":f"API endpoint {path} allows arbitrary origins.","fix":"Restrict CORS on API endpoints to trusted origins only."})
                score -= 20
                break
    if not findings:
        findings.append({"severity":"low","title":"CORS policy looks safe","status":"pass","detail":"No wildcard, reflected, or null origins detected."})
    return {"id":"cors","name":"CORS Policy","icon":"🌍","score":max(0,score),"findings":findings}

# ── 12. WAF & Rate Limiting ───────────────────────────────────────────────────
def scan_waf(host):
    findings, score = [], 100
    base = f"https://{host}"
    r = _get(base)
    if not r:
        return {"id":"waf","name":"WAF & Rate Limiting","icon":"🧱","score":50,"findings":[]}
    hstr = str(r.headers).lower()
    SIGS = [("cloudflare","Cloudflare"),("cf-ray","Cloudflare"),("sucuri","Sucuri"),
            ("x-iinfo","Imperva"),("x-akamai","Akamai"),("x-fortigate","FortiGate"),
            ("x-sucuri-id","Sucuri"),("x-fw-server","Fortiweb")]
    waf = next((n for k,n in SIGS if k in hstr), None)
    if waf:
        findings.append({"severity":"low","title":f"WAF detected: {waf}","status":"pass","detail":f"{waf} protection active."})
    else:
        findings.append({"severity":"medium","title":"No WAF detected","status":"fail","detail":"No WAF signatures found.","fix":"Add Cloudflare (free tier) or another WAF."})
        score -= 15
    # Rate limiting
    rl = any(h in {k.lower() for k in r.headers} for h in ["x-ratelimit-limit","ratelimit-limit","retry-after","x-rate-limit"])
    if rl:
        findings.append({"severity":"low","title":"Rate limiting headers present","status":"pass","detail":"Rate limiting configured."})
    else:
        findings.append({"severity":"medium","title":"No rate limiting headers","status":"fail","detail":"No rate limit headers detected.","fix":"Add rate limiting via Cloudflare, Nginx, or your app."})
        score -= 10
    # Attack probe test
    probe = _get(f"{base}/?q=<script>alert(1)</script>&id=1'", timeout=5)
    if probe and probe.status_code == 403:
        findings.append({"severity":"low","title":"WAF blocks attack probes","status":"pass","detail":"XSS/SQLi probe returned 403."})
    elif waf:
        findings.append({"severity":"low","title":"WAF present (probe not blocked at edge)","status":"pass","detail":"WAF detected but probe not blocked — may use different detection."})
    return {"id":"waf","name":"WAF & Rate Limiting","icon":"🧱","score":max(0,min(100,score)),"findings":findings}

# ── 13. Server Security ───────────────────────────────────────────────────────
def scan_server(host):
    findings, score = [], 100
    base = f"https://{host}"
    r = _get(base)
    if not r:
        return {"id":"server","name":"Server Security","icon":"⚙️","score":50,"findings":[]}
    h = {k.lower(): v for k, v in r.headers.items()}
    # Version disclosure
    srv = h.get("server","")
    if re.search(r"[\d.]{3,}", srv):
        findings.append({"severity":"medium","title":f"Server version disclosed: {srv}","status":"fail","detail":"Exact version enables CVE targeting.","fix":"Set: ServerTokens Prod (Apache) or server_tokens off (Nginx)."})
        score -= 10
    elif srv:
        findings.append({"severity":"low","title":f"Server: {srv} (no version)","status":"pass","detail":"Software type visible but no version."})
    xpb = h.get("x-powered-by","")
    if xpb:
        findings.append({"severity":"medium","title":f"X-Powered-By: {xpb}","status":"fail","detail":"Tech stack disclosed.","fix":"Remove X-Powered-By header."})
        score -= 10
    # Tech fingerprinting
    body = r.text.lower()[:5000]
    TECHS = [("wp-content","WordPress"),("wp-json","WordPress"),("drupal.js","Drupal"),
             ("joomla","Joomla"),("django","Django"),("laravel","Laravel"),
             ("rails","Ruby on Rails"),("next.js","Next.js"),("__next","Next.js")]
    for sig, tech in TECHS:
        if sig in body or sig in str(r.headers).lower():
            findings.append({"severity":"low","title":f"Technology detected: {tech}","status":"info","detail":f"{tech} fingerprint found."})
            break
    # HTTP/2
    if r.raw and hasattr(r.raw, 'version') and r.raw.version == 20:
        findings.append({"severity":"low","title":"HTTP/2 enabled","status":"pass","detail":"Modern HTTP/2 protocol in use."})
    # Error page
    r404 = _get(f"{base}/this-page-xyz987-does-not-exist", allow_redirects=False)
    if r404 and re.search(r"(apache|nginx|php|traceback|exception|stack trace)", r404.text.lower()[:2000]):
        findings.append({"severity":"medium","title":"Error pages reveal server info","status":"fail","detail":"Stack details in error responses.","fix":"Configure custom error pages."})
        score -= 10
    else:
        findings.append({"severity":"low","title":"Error pages clean","status":"pass","detail":"No server info in error responses."})
    # Directory listing
    for path in ["/images/","/assets/","/uploads/","/static/","/files/"]:
        rd = _get(f"{base}{path}", allow_redirects=False, timeout=4)
        if rd and rd.status_code == 200 and re.search(r"(index of|directory listing)", rd.text.lower()[:500]):
            findings.append({"severity":"high","title":f"Directory listing at {path}","status":"fail","detail":"File listing publicly visible.","fix":"Add Options -Indexes to server config."})
            score -= 20; break
    else:
        findings.append({"severity":"low","title":"No directory listing","status":"pass","detail":"Common directories don't expose file lists."})
    # TRACE method (XST)
    try:
        rt = requests.request("TRACE", f"https://{host}", headers={"User-Agent":UA}, timeout=5)
        if rt.status_code == 200 and "TRACE" in rt.text.upper():
            findings.append({"severity":"medium","title":"TRACE method enabled (XST risk)","status":"fail","detail":"HTTP TRACE can leak cookies via XST attack.","fix":"Disable TRACE: TraceEnable Off (Apache) or limit_except (Nginx)."})
            score -= 10
    except Exception:
        pass
    return {"id":"server","name":"Server Security","icon":"⚙️","score":max(0,score),"findings":findings}

# ── 14. API & Injection ───────────────────────────────────────────────────────
def scan_api(host):
    findings, score = [], 100
    base = f"https://{host}"
    r = _get(base)
    html = r.text if r else ""
    # Secrets in source
    SECRETS = [
        (r"AKIA[0-9A-Z]{16}","AWS Access Key ID"),
        (r"(?i)api[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]","API Key"),
        (r"ghp_[A-Za-z0-9]{36}","GitHub Personal Token"),
        (r"sk-[A-Za-z0-9]{48}","OpenAI API Key"),
        (r"sk_live_[A-Za-z0-9]{24,}","Stripe Live Key"),
        (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}","SendGrid API Key"),
        (r"(?i)password\s*[=:]\s*['\"]([^'\"]{8,})['\"]","Hardcoded Password"),
        (r"(?i)secret\s*[=:]\s*['\"]([^'\"]{10,})['\"]","Hardcoded Secret"),
        (r"Bearer [A-Za-z0-9_\-\.]{20,}","Bearer Token"),
    ]
    for pat, label in SECRETS:
        if re.search(pat, html):
            findings.append({"severity":"critical","title":f"Exposed in source: {label}","status":"fail","detail":f"Pattern matching {label} found in page source.","fix":f"Remove from source immediately. Rotate the credential. Use env vars."})
            score -= 35
    # GraphQL introspection
    for gql_path in ["/graphql","/api/graphql","/gql"]:
        rg = _get(f"{base}{gql_path}", method="POST", data={"query":"{ __schema { types { name } } }"}, timeout=5)
        if rg and rg.status_code == 200 and "__schema" in rg.text:
            findings.append({"severity":"medium","title":"GraphQL introspection enabled","status":"fail","detail":f"Schema fully exposed at {gql_path}.","fix":"Disable introspection in production. Use query whitelisting."})
            score -= 15; break
    # SQLi
    SQL_ERRORS = ["sql syntax","mysql_fetch","ora-","sqlstate","pg_query","sqlite_","unclosed quotation"]
    for probe in ["/?id=1'","/?q=1'%20OR%201=1--","/?search=test'"]:
        rp = _get(f"{base}{probe}", timeout=5)
        if rp:
            for err in SQL_ERRORS:
                if err in rp.text.lower():
                    findings.append({"severity":"critical","title":"SQL injection — DB error exposed","status":"fail","detail":f"Database error for probe: {probe}","fix":"Use parameterised queries everywhere. Never concatenate SQL strings."})
                    score -= 40; break
    # Reflected XSS
    xss = "<script>alert('xss')</script>"
    rx = _get(f"{base}/?q={xss}", timeout=5)
    if rx and xss in rx.text:
        findings.append({"severity":"high","title":"Reflected XSS detected","status":"fail","detail":"XSS payload reflected unencoded.","fix":"HTML-encode all user input before rendering. Add CSP."})
        score -= 30
    # Unauthenticated API
    for api_path in ["/api/users","/api/admin","/api/config","/api/v1/users"]:
        ra = _get(f"{base}{api_path}", timeout=4)
        if ra and ra.status_code == 200 and len(ra.content) > 50:
            try:
                import json
                json.loads(ra.text)
                findings.append({"severity":"high","title":f"Unauthenticated API: {api_path}","status":"fail","detail":f"{api_path} returns data without auth.","fix":"Add authentication/authorization to all API endpoints."})
                score -= 25; break
            except Exception:
                pass
    if score == 100:
        findings.append({"severity":"low","title":"No obvious injection vulnerabilities","status":"pass","detail":"Basic SQLi, XSS, and secret probes passed."})
    return {"id":"api","name":"API & Injection","icon":"🔌","score":max(0,score),"findings":findings}

# ── Master Runner ─────────────────────────────────────────────────────────────
from app.services.pentest_modules import (
    scan_blind_sqli, scan_ssti, scan_xxe, scan_ssrf, scan_path_traversal,
    scan_auth, scan_jwt, scan_idor, scan_command_injection,
    scan_business_logic, scan_cve, scan_cloud_infra, scan_owasp_api, scan_websocket
)
from app.services.pentest_modules_v2 import (
    scan_request_smuggling, scan_oauth, scan_open_redirect, scan_session,
    scan_cache_poisoning, scan_crlf, scan_dom_xss, scan_secrets,
    scan_graphql_deep, scan_cert_transparency
)
from app.services.pentest_modules_v3 import (
    scan_csrf, scan_nosql_injection, scan_file_upload, scan_deserialization,
    scan_ldap_injection, scan_xpath_injection, scan_host_header,
    scan_email_injection, scan_clickjacking
)
from app.services.pentest_modules_v4 import (
    scan_reflected_xss, scan_stored_xss, scan_error_handling, scan_weak_crypto,
    scan_2fa_bypass, scan_dependency_sca, scan_recon, scan_app_dos,
    scan_http_param_pollution, scan_race_condition
)

# ── Original 14 modules (weighted to 60% of total) ────────────────────────────
MODULES_CORE = [
    ("ssl",           scan_ssl,           0.055),
    ("tls_deep",      scan_tls_deep,      0.045),
    ("headers",       scan_headers,       0.055),
    ("content",       scan_content,       0.045),
    ("dns",           scan_dns,           0.040),
    ("dns_adv",       scan_dns_advanced,  0.025),
    ("cookies",       scan_cookies,       0.035),
    ("info",          scan_info,          0.030),
    ("files",         scan_files,         0.045),
    ("ports",         scan_ports,         0.040),
    ("cors",          scan_cors,          0.035),
    ("waf",           scan_waf,           0.030),
    ("server",        scan_server,        0.035),
    ("api",           scan_api,           0.040),
]

# ── New pentest modules (weighted to 40% of total) ────────────────────────────
MODULES_PENTEST = [
    ("blind_sqli",    scan_blind_sqli,    0.040),
    ("ssti",          scan_ssti,          0.035),
    ("xxe",           scan_xxe,           0.025),
    ("ssrf",          scan_ssrf,          0.035),
    ("path_traversal",scan_path_traversal,0.030),
    ("auth",          scan_auth,          0.040),
    ("jwt",           scan_jwt,           0.025),
    ("idor",          scan_idor,          0.030),
    ("cmd_injection", scan_command_injection, 0.035),
    ("business_logic",scan_business_logic,0.025),
    ("cve",           scan_cve,           0.030),
    ("cloud_infra",   scan_cloud_infra,   0.025),
    ("owasp_api",     scan_owasp_api,     0.030),
    ("websocket",     scan_websocket,     0.020),
]

# MODULES redefined below after v2 modules

def run_all_scanners(hostname: str) -> dict:
    weighted = {}
    def _run(args):
        sid, fn, w = args
        try:
            return sid, fn(hostname), w
        except Exception as e:
            return sid, {"id":sid,"name":sid,"icon":"⚠️","score":50,"findings":[{"severity":"medium","title":"Scanner error","status":"error","detail":str(e)}]}, w
    with concurrent.futures.ThreadPoolExecutor(max_workers=57) as ex:
        for sid, result, w in ex.map(_run, MODULES):
            weighted[sid] = (result, w)
    cats        = [r for r, _ in weighted.values()]
    total_w     = sum(w for _, w in weighted.values())
    overall     = round(sum(r["score"] * (w / total_w) for r, w in weighted.values()))
    overall = max(0, min(100, overall))
    grade   = "A" if overall>=90 else "B" if overall>=80 else "C" if overall>=70 else "D" if overall>=60 else "F"
    sev = {"critical":0,"high":0,"medium":0,"low":0}
    for c in cats:
        for f in c.get("findings",[]):
            if f.get("status")=="fail" and f.get("severity") in sev:
                sev[f["severity"]] += 1
    return {"score":overall,"grade":grade,"severity_counts":sev,
            "categories":cats,"total_checks":sum(len(c.get("findings",[])) for c in cats)}

# Modules are now defined above — patching to add v2 pentest modules
MODULES_PENTEST_V2 = [
    ("request_smuggling", scan_request_smuggling, 0.020),
    ("oauth",             scan_oauth,             0.025),
    ("open_redirect",     scan_open_redirect,     0.020),
    ("session",           scan_session,           0.030),
    ("cache_poisoning",   scan_cache_poisoning,   0.020),
    ("crlf",              scan_crlf,              0.020),
    ("dom_xss",           scan_dom_xss,           0.025),
    ("secrets",           scan_secrets,           0.035),
    ("graphql_deep",      scan_graphql_deep,      0.020),
    ("cert_transparency", scan_cert_transparency, 0.015),
]

# MODULES redefined below — see final definition

# ── Group A: 9 modules ────────────────────────────────────────────────────────
MODULES_GROUP_A = [
    ("csrf",               scan_csrf,               0.025),
    ("nosql_injection",    scan_nosql_injection,    0.030),
    ("file_upload",        scan_file_upload,        0.030),
    ("deserialization",    scan_deserialization,    0.025),
    ("ldap_injection",     scan_ldap_injection,     0.020),
    ("xpath_injection",    scan_xpath_injection,    0.020),
    ("host_header",        scan_host_header,        0.025),
    ("email_injection",    scan_email_injection,    0.020),
    ("clickjacking",       scan_clickjacking,       0.020),
]

# ── Group B: 10 modules ───────────────────────────────────────────────────────
MODULES_GROUP_B = [
    ("reflected_xss",      scan_reflected_xss,      0.035),
    ("stored_xss",         scan_stored_xss,         0.035),
    ("error_handling",     scan_error_handling,     0.025),
    ("weak_crypto",        scan_weak_crypto,        0.025),
    ("2fa_bypass",         scan_2fa_bypass,         0.020),
    ("dependency_sca",     scan_dependency_sca,     0.025),
    ("recon",              scan_recon,              0.015),
    ("app_dos",            scan_app_dos,            0.020),
    ("http_param_pollution",scan_http_param_pollution,0.015),
    ("race_condition",     scan_race_condition,     0.025),
]

MODULES = MODULES_CORE + MODULES_PENTEST + MODULES_PENTEST_V2 + MODULES_GROUP_A + MODULES_GROUP_B

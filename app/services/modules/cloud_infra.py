"""
Module 19: Cloud & Infrastructure Security
AWS/GCP/Azure metadata exposure, S3 bucket misconfig, Docker API,
Kubernetes API, cloud storage, internal service exposure
"""
import re, json
import concurrent.futures

UA      = "Mozilla/5.0 (SecureScan/2.0; +https://securescan.io)"
TIMEOUT = 7

def _get(url, headers=None, timeout=None, allow_redirects=True):
    try:
        import requests
        h = {"User-Agent": UA, **(headers or {})}
        return requests.get(url, headers=h, timeout=timeout or TIMEOUT, allow_redirects=allow_redirects)
    except Exception:
        return None

# ── Cloud metadata endpoint exposure ──────────────────────────────────────────
def test_cloud_metadata(base: str) -> list:
    """Test if SSRF can reach cloud metadata endpoints (via URL params)"""
    findings = []
    METADATA_TARGETS = [
        # AWS IMDSv1 (most dangerous — no auth required)
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         ["role", "RoleName"], "AWS IAM credentials via IMDSv1"),
        ("http://169.254.169.254/latest/user-data",
         ["#!/bin", "cloud-init", "password", "key"], "AWS user-data script"),
        ("http://169.254.169.254/latest/meta-data/",
         ["ami-id", "instance-id", "hostname", "local-ipv4"], "AWS EC2 metadata"),
        # GCP
        ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         ["access_token", "token_type"], "GCP service account token"),
        # Azure
        ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         ["access_token", "client_id"], "Azure managed identity token"),
    ]
    URL_PARAMS = ["url", "src", "href", "link", "redirect", "next", "return",
                  "fetch", "load", "proxy", "callback", "endpoint", "target"]
    for target_url, indicators, label in METADATA_TARGETS[:3]:
        for param in URL_PARAMS[:5]:
            r = _get(f"{base}?{param}={target_url}", timeout=5)
            if r:
                for indicator in indicators:
                    if indicator in r.text:
                        findings.append({
                            "severity": "critical",
                            "title": f"SSRF → {label}",
                            "status": "fail",
                            "detail": f"SSRF via param '{param}' reached {label}. Cloud credentials may be exposed.",
                            "fix": "Block requests to 169.254.169.254 and metadata endpoints at network level. Validate/allowlist URLs. Use IMDSv2.",
                        })
                        return findings
    return findings

# ── AWS IMDSv2 check ───────────────────────────────────────────────────────────
def test_imds_version(base: str) -> list:
    """Check if AWS IMDSv1 (no-hop-limit token) is accessible from target"""
    findings = []
    # Attempt direct metadata access (only works if scanner is on same cloud network,
    # but we test SSRF paths too)
    r = _get("http://169.254.169.254/latest/meta-data/", timeout=2)
    if r and r.status_code == 200 and "ami-id" in r.text:
        findings.append({
            "severity": "critical",
            "title": "AWS IMDSv1 accessible from scanner network",
            "status": "fail",
            "detail": "EC2 instance metadata accessible without IMDSv2 token. IAM role credentials extractable.",
            "fix": "Enable IMDSv2 (require session-oriented authentication): aws ec2 modify-instance-metadata-options --http-tokens required",
        })
    return findings

# ── S3 bucket misconfiguration ────────────────────────────────────────────────
def test_s3_buckets(host: str) -> list:
    findings = []
    domain_parts = host.split(".")
    # Generate bucket name guesses from domain
    base_name = domain_parts[0] if len(domain_parts) >= 2 else host
    BUCKET_NAMES = [
        base_name,
        f"{base_name}-assets",
        f"{base_name}-backup",
        f"{base_name}-backups",
        f"{base_name}-static",
        f"{base_name}-media",
        f"{base_name}-uploads",
        f"{base_name}-data",
        f"{base_name}-logs",
        f"{base_name}-dev",
        f"{base_name}-staging",
        f"{base_name}-prod",
        f"{base_name}-production",
    ]
    REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]
    def chk_bucket(name):
        for region in REGIONS[:2]:
            for url in [
                f"https://{name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{name}",
                f"https://{name}.s3.{region}.amazonaws.com",
            ]:
                r = _get(url, timeout=4)
                if r:
                    if r.status_code == 200:
                        body = r.text
                        if "<ListBucketResult" in body or "<Key>" in body:
                            return (name, url, "publicly listable", "critical")
                        elif len(r.content) > 100:
                            return (name, url, "accessible", "high")
                    elif r.status_code == 403:
                        return (name, url, "exists but private", "low")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = [r for r in ex.map(chk_bucket, BUCKET_NAMES[:8]) if r]

    for name, url, status, sev in results:
        if sev in ("critical", "high"):
            findings.append({
                "severity": sev,
                "title": f"S3 bucket '{name}' is {status}: {url}",
                "status": "fail",
                "detail": f"S3 bucket {url} is publicly accessible. Sensitive files may be exposed.",
                "fix": "Set S3 bucket ACL to private. Enable Block Public Access. Use bucket policies to restrict access. Audit bucket contents.",
            })
        elif sev == "low":
            findings.append({
                "severity": "low",
                "title": f"S3 bucket found (private): {name}",
                "status": "info",
                "detail": f"S3 bucket exists at {url} but access is restricted.",
            })
    return findings

# ── Docker API exposure ────────────────────────────────────────────────────────
def test_docker_api(host: str) -> list:
    findings = []
    DOCKER_PORTS = [2375, 2376, 2377, 4243]
    import socket
    for port in DOCKER_PORTS:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            r = _get(f"http://{host}:{port}/v1.41/info", timeout=3)
            if r and r.status_code == 200:
                data = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
                label = data.get("Name", "unknown")
                findings.append({
                    "severity": "critical",
                    "title": f"Docker API exposed on port {port} (host: {label})",
                    "status": "fail",
                    "detail": "Unauthenticated Docker API allows full container and host control — equivalent to root shell.",
                    "fix": "Immediately close Docker API port. Never expose Docker socket to internet. Use TLS with client certificates if remote access needed.",
                })
                return findings
            elif r:
                findings.append({
                    "severity": "critical",
                    "title": f"Docker API port {port} open",
                    "status": "fail",
                    "detail": f"Docker daemon port {port} is open. May allow container escape to host.",
                    "fix": "Block Docker API ports with firewall. Enable TLS authentication.",
                })
                return findings
        except Exception:
            pass
    return findings

# ── Kubernetes API exposure ───────────────────────────────────────────────────
def test_kubernetes_api(host: str) -> list:
    findings = []
    import socket
    K8S_PORTS = [6443, 8443, 8080, 10250, 10255]
    for port in K8S_PORTS:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            proto = "https" if port in (6443, 8443, 10250) else "http"
            r = _get(f"{proto}://{host}:{port}/api/v1/namespaces", timeout=4)
            if r and r.status_code == 200:
                if "namespaces" in r.text or "items" in r.text:
                    findings.append({
                        "severity": "critical",
                        "title": f"Kubernetes API server exposed on port {port}",
                        "status": "fail",
                        "detail": "Unauthenticated Kubernetes API access. Full cluster control possible.",
                        "fix": "Restrict K8s API to internal network. Enable RBAC. Disable anonymous auth: --anonymous-auth=false",
                    })
                    return findings
            # kubelet read-only
            if port == 10255:
                r2 = _get(f"http://{host}:10255/pods", timeout=4)
                if r2 and r2.status_code == 200 and "pods" in r2.text.lower():
                    findings.append({
                        "severity": "high",
                        "title": "Kubernetes kubelet read-only API exposed (port 10255)",
                        "status": "fail",
                        "detail": "Kubelet read-only port exposes pod list and environment variables.",
                        "fix": "Disable kubelet read-only port: --read-only-port=0",
                    })
                    return findings
        except Exception:
            pass
    return findings

# ── Exposed internal services ─────────────────────────────────────────────────
def test_internal_services(host: str) -> list:
    findings = []
    SERVICES = [
        (9200,  "Elasticsearch",   ["_cluster", "indices", "mappings"],  "http"),
        (9300,  "Elasticsearch transport", [],                           "http"),
        (6379,  "Redis",           [],                                    "tcp"),
        (27017, "MongoDB",         ["ok", "ismaster"],                   "http"),
        (5984,  "CouchDB",         ["couchdb", "version"],               "http"),
        (8500,  "Consul",          ["agent/self", "services"],           "http"),
        (4001,  "etcd",            ["keys", "version"],                  "http"),
        (2181,  "Zookeeper",       [],                                    "tcp"),
        (9090,  "Prometheus",      ["/metrics", "prometheus"],           "http"),
        (3000,  "Grafana",         ["grafana", "dashboard"],             "http"),
        (8888,  "Jupyter Notebook",["jupyter", "notebook"],              "http"),
        (8161,  "ActiveMQ",        ["activemq", "broker"],               "http"),
        (15672, "RabbitMQ mgmt",   ["rabbitmq", "overview"],             "http"),
        (4040,  "Spark UI",        ["spark", "stages"],                  "http"),
    ]
    import socket
    def chk(args):
        port, name, indicators, proto = args
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            if proto == "http" and indicators:
                r = _get(f"http://{host}:{port}", timeout=3)
                if r and r.status_code == 200:
                    body = r.text.lower()
                    if any(ind.lower() in body for ind in indicators):
                        return (port, name, "confirmed open and responding")
            return (port, name, "port open")
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = [r for r in ex.map(chk, SERVICES) if r]
    for port, name, status in results:
        sev = "critical" if name in ("Elasticsearch", "Redis", "MongoDB", "etcd", "Jupyter Notebook") else "high"
        findings.append({
            "severity": sev,
            "title": f"{name} exposed on port {port} ({status})",
            "status": "fail",
            "detail": f"Internal service {name} is reachable from the internet on port {port}.",
            "fix": f"Firewall port {port}. {name} should only be accessible from internal network or via VPN.",
        })
    return findings

# ── Cloud storage misconfiguration (GCS, Azure Blob) ──────────────────────────
def test_cloud_storage(host: str) -> list:
    findings = []
    base_name = host.split(".")[0]
    # GCS
    for name in [base_name, f"{base_name}-assets", f"{base_name}-backup"]:
        r = _get(f"https://storage.googleapis.com/{name}?list-type=2", timeout=4)
        if r and r.status_code == 200 and ("<ListBucketResult" in r.text or "<Key>" in r.text):
            findings.append({
                "severity": "critical",
                "title": f"GCS bucket '{name}' publicly listable",
                "status": "fail",
                "detail": f"Google Cloud Storage bucket storage.googleapis.com/{name} is publicly accessible.",
                "fix": "Set GCS bucket IAM to remove allUsers/allAuthenticatedUsers. Enable uniform bucket-level access.",
            })
            return findings
    # Azure Blob
    for name in [base_name, f"{base_name}storage", f"{base_name}assets"]:
        r = _get(f"https://{name}.blob.core.windows.net?restype=container&comp=list", timeout=4)
        if r and r.status_code == 200 and "<Blobs>" in r.text:
            findings.append({
                "severity": "critical",
                "title": f"Azure Blob container '{name}' publicly listable",
                "status": "fail",
                "detail": f"Azure Blob Storage {name}.blob.core.windows.net is publicly accessible.",
                "fix": "Set Azure container access level to Private. Use Shared Access Signatures for temporary access.",
            })
            return findings
    return findings

# ── Master cloud scanner ───────────────────────────────────────────────────────
def scan_cloud_infrastructure(host: str) -> dict:
    findings = []
    score    = 100
    base     = f"https://{host}"

    tests = [
        ("Cloud Metadata SSRF",  lambda: test_cloud_metadata(base)),
        ("S3 Buckets",           lambda: test_s3_buckets(host)),
        ("Docker API",           lambda: test_docker_api(host)),
        ("Kubernetes API",       lambda: test_kubernetes_api(host)),
        ("Internal Services",    lambda: test_internal_services(host)),
        ("Cloud Storage",        lambda: test_cloud_storage(host)),
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn): name for name, fn in tests}
        for future, name in futures.items():
            try:
                results = future.result(timeout=30)
                for f in results:
                    findings.append(f)
                    if f["status"] == "fail":
                        score -= {"critical": 35, "high": 20, "medium": 10, "low": 5}.get(f["severity"], 5)
            except Exception:
                pass

    if not findings:
        findings.append({
            "severity": "low",
            "title": "No cloud/infrastructure exposures detected",
            "status": "pass",
            "detail": "S3, GCS, Azure, Docker, Kubernetes, and internal service checks passed.",
        })

    return {
        "id":       "cloud_infra",
        "name":     "Cloud & Infrastructure",
        "icon":     "☁️",
        "score":    max(0, score),
        "findings": findings,
    }

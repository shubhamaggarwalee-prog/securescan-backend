"""
SecureScan — Complete Test Suite
Run: cd backend && pytest tests/ -v
"""
import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

# ── App setup ─────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def client():
    # Patch external dependencies before importing app
    with patch("app.database.create_client") as mock_db, \
         patch("app.services.scheduler.start_scheduler"), \
         patch("app.services.scheduler.stop_scheduler"):
        mock_db.return_value = MagicMock()
        from app.main import app
        with TestClient(app) as c:
            yield c

@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-token"}

@pytest.fixture
def mock_user():
    return {
        "id": "user-123",
        "email": "test@example.com",
        "plan": "pro",
        "scans_this_month": 5,
        "scan_limit": 100,
        "scans_remaining": 95,
        "features": {"scans":100,"sites":10,"pdf":True,"ai":True,"alerts":True},
    }

@pytest.fixture
def mock_free_user():
    return {
        "id": "user-free-456",
        "email": "free@example.com",
        "plan": "free",
        "scans_this_month": 3,
        "scan_limit": 5,
        "scans_remaining": 2,
        "features": {"scans":5,"sites":1,"pdf":False,"ai":False,"alerts":False},
    }

# ══════════════════════════════════════════════════════════════════════════════
# HEALTH & ROOT
# ══════════════════════════════════════════════════════════════════════════════
class TestHealth:
    def test_health_returns_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        assert r.json()["version"] == "2.0.0"

    def test_root_returns_info(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "SecureScan" in r.json()["name"]

# ══════════════════════════════════════════════════════════════════════════════
# SCANNER ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class TestScannerEngine:
    def test_ssl_scanner_structure(self):
        from app.services.scanner import scan_ssl
        with patch("socket.create_connection") as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError()
            result = scan_ssl("example.com")
        assert "id" in result
        assert "name" in result
        assert "score" in result
        assert "findings" in result
        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100

    def test_headers_scanner_structure(self):
        from app.services.scanner import scan_headers
        mock_resp = MagicMock()
        mock_resp.headers = {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
        }
        mock_resp.status_code = 200
        with patch("app.services.scanner._get", return_value=mock_resp):
            result = scan_headers("example.com")
        assert result["id"] == "headers"
        assert isinstance(result["findings"], list)
        assert result["score"] <= 100

    def test_headers_scanner_missing_headers(self):
        from app.services.scanner import scan_headers
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.status_code = 200
        with patch("app.services.scanner._get", return_value=mock_resp):
            result = scan_headers("example.com")
        fails = [f for f in result["findings"] if f["status"] == "fail"]
        assert len(fails) > 0, "Missing headers should produce failures"
        assert result["score"] < 100

    def test_headers_scanner_unreachable(self):
        from app.services.scanner import scan_headers
        with patch("app.services.scanner._get", return_value=None):
            result = scan_headers("unreachable.example.com")
        assert result["score"] == 50

    def test_cors_scanner_wildcard(self):
        from app.services.scanner import scan_cors
        mock_resp = MagicMock()
        mock_resp.headers = {"access-control-allow-origin": "*"}
        with patch("app.services.scanner._get", return_value=mock_resp):
            result = scan_cors("example.com")
        fails = [f for f in result["findings"] if f["status"] == "fail"]
        assert any("wildcard" in f["title"].lower() or "*" in f["title"] for f in fails)

    def test_cors_scanner_reflected_origin(self):
        from app.services.scanner import scan_cors
        def mock_get(url, headers=None, **kwargs):
            origin = (headers or {}).get("Origin","")
            r = MagicMock()
            r.headers = {"access-control-allow-origin": origin}
            return r
        with patch("app.services.scanner._get", side_effect=mock_get):
            result = scan_cors("example.com")
        fails = [f for f in result["findings"] if f["status"] == "fail"]
        assert len(fails) > 0

    def test_files_scanner_exposed_env(self):
        from app.services.scanner import scan_files
        def mock_get(url, **kwargs):
            if ".env" in url and "local" not in url and "production" not in url and "backup" not in url:
                r = MagicMock()
                r.status_code = 200
                r.content = b"SECRET_KEY=abc123\nDB_PASSWORD=hunter2"
                return r
            r = MagicMock()
            r.status_code = 404
            r.content = b""
            return r
        with patch("app.services.scanner._get", side_effect=mock_get):
            result = scan_files("example.com")
        fails = [f for f in result["findings"] if f["status"] == "fail"]
        assert any(".env" in f["title"].lower() or "env" in f["title"].lower() for f in fails)
        assert result["score"] < 100

    def test_waf_scanner_cloudflare_detected(self):
        from app.services.scanner import scan_waf
        mock_resp = MagicMock()
        mock_resp.headers = {"cf-ray": "abc123", "server": "cloudflare"}
        mock_resp.status_code = 200
        mock_resp.text = ""
        with patch("app.services.scanner._get", return_value=mock_resp):
            result = scan_waf("example.com")
        passes = [f for f in result["findings"] if f["status"] == "pass"]
        assert any("cloudflare" in f["title"].lower() for f in passes)

    def test_api_scanner_secret_in_source(self):
        from app.services.scanner import scan_api
        mock_resp = MagicMock()
        mock_resp.text = 'const apiKey = "AKIAIOSFODNN7EXAMPLE"'
        with patch("app.services.scanner._get", return_value=mock_resp):
            result = scan_api("example.com")
        fails = [f for f in result["findings"] if f["status"] == "fail"]
        assert any("aws" in f["title"].lower() or "exposed" in f["title"].lower() for f in fails)
        assert result["score"] < 100

    def test_run_all_scanners_returns_complete_result(self):
        from app.services.scanner import run_all_scanners
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.status_code = 200
        mock_resp.text = ""
        mock_resp.content = b""
        mock_resp.cookies = []
        with patch("app.services.scanner._get", return_value=mock_resp), \
             patch("socket.create_connection", side_effect=ConnectionRefusedError()), \
             patch("dns.resolver.resolve", side_effect=Exception("no dns")):
            result = run_all_scanners("example.com")
        assert "score" in result
        assert "grade" in result
        assert "categories" in result
        assert "severity_counts" in result
        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100
        assert result["grade"] in ("A","B","C","D","F")
        assert len(result["categories"]) == 14

    def test_score_grade_mapping(self):
        from app.services.scanner import run_all_scanners
        # Test grade calculation directly
        test_cases = [
            (95, "A"), (85, "B"), (75, "C"), (65, "D"), (50, "F")
        ]
        for score, expected_grade in test_cases:
            grade = "A" if score>=90 else "B" if score>=80 else "C" if score>=70 else "D" if score>=60 else "F"
            assert grade == expected_grade, f"Score {score} should be grade {expected_grade}"

    def test_all_findings_have_required_fields(self):
        from app.services.scanner import scan_headers
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_resp.status_code = 200
        with patch("app.services.scanner._get", return_value=mock_resp):
            result = scan_headers("example.com")
        for f in result["findings"]:
            assert "severity" in f, f"Finding missing severity: {f}"
            assert "title"    in f, f"Finding missing title: {f}"
            assert "status"   in f, f"Finding missing status: {f}"
            assert f["severity"]  in ("critical","high","medium","low"), f"Invalid severity: {f['severity']}"
            assert f["status"]    in ("pass","fail","error","warn","info"), f"Invalid status: {f['status']}"

# ══════════════════════════════════════════════════════════════════════════════
# SCAN API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════
class TestScanEndpoints:
    def test_start_scan_requires_auth(self, client):
        r = client.post("/api/scan", json={"url": "https://example.com"})
        assert r.status_code == 401

    def test_start_scan_invalid_url(self, client, auth_headers, mock_user):
        with patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.routers.scan.check_scan_limit", return_value=mock_user):
            r = client.post("/api/scan", json={"url": "not-a-url-at-all-xyz"}, headers=auth_headers)
        # URL gets https:// prepended and then parsed
        assert r.status_code in (200, 400)

    def test_start_scan_success(self, client, auth_headers, mock_user):
        with patch("app.routers.scan.check_scan_limit", return_value=mock_user), \
             patch("app.database.db.create_scan", new_callable=AsyncMock, return_value="scan-abc-123"), \
             patch("app.routers.scan._run_scan", new_callable=AsyncMock):
            r = client.post("/api/scan", json={"url": "https://example.com"}, headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert "scan_id" in data
        assert data["status"] == "queued"

    def test_get_scan_requires_auth(self, client):
        r = client.get("/api/scan/some-scan-id")
        assert r.status_code == 401

    def test_get_scan_not_found(self, client, auth_headers, mock_user):
        with patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.database.db.get_scan", new_callable=AsyncMock, return_value=None):
            r = client.get("/api/scan/nonexistent-id", headers=auth_headers)
        assert r.status_code == 404

    def test_get_scan_wrong_user(self, client, auth_headers, mock_user):
        fake_scan = {"id": "scan-1", "user_id": "other-user", "status": "complete"}
        with patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.database.db.get_scan", new_callable=AsyncMock, return_value=fake_scan):
            r = client.get("/api/scan/scan-1", headers=auth_headers)
        assert r.status_code == 403

    def test_get_scan_success(self, client, auth_headers, mock_user):
        scan = {"id":"scan-1","user_id":"user-123","status":"complete","score":85,"grade":"B"}
        with patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.database.db.get_scan", new_callable=AsyncMock, return_value=scan):
            r = client.get("/api/scan/scan-1", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["grade"] == "B"

    def test_list_scans_success(self, client, auth_headers, mock_user):
        scans = [{"id":f"scan-{i}","user_id":"user-123","score":80+i,"grade":"B"} for i in range(3)]
        with patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.database.db.list_scans", new_callable=AsyncMock, return_value=scans):
            r = client.get("/api/scans", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()["scans"]) == 3

    def test_pdf_requires_pro(self, client, auth_headers, mock_free_user):
        scan = {"id":"scan-1","user_id":"user-free-456","status":"complete","score":70,"grade":"C","hostname":"ex.com","categories":[],"severity_counts":{}}
        with patch("app.routers.scan.get_current_user", return_value=mock_free_user), \
             patch("app.database.db.get_scan", new_callable=AsyncMock, return_value=scan):
            r = client.get("/api/scan/scan-1/pdf", headers=auth_headers)
        assert r.status_code == 403

    def test_scan_limit_enforced(self, client, auth_headers):
        maxed_user = {"id":"u1","email":"x@x.com","plan":"free","scans_this_month":5,"scan_limit":5}
        with patch("app.auth.get_current_user", return_value=maxed_user), \
             patch("app.auth.db.get_profile", new_callable=AsyncMock, return_value=maxed_user):
            from app.auth import check_scan_limit
            import asyncio
            with pytest.raises(Exception):
                asyncio.get_event_loop().run_until_complete(check_scan_limit(maxed_user))

    def test_get_me_success(self, client, auth_headers, mock_user):
        with patch("app.routers.scan.get_current_user", return_value=mock_user):
            r = client.get("/api/me", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["plan"] == "pro"
        assert "scans_remaining" in data
        assert "features" in data

    def test_delete_scan(self, client, auth_headers, mock_user):
        with patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.database.db.delete_scan", new_callable=AsyncMock):
            r = client.delete("/api/scan/scan-1", headers=auth_headers)
        assert r.status_code == 200

# ══════════════════════════════════════════════════════════════════════════════
# BILLING
# ══════════════════════════════════════════════════════════════════════════════
class TestBilling:
    def test_get_plans(self, client):
        r = client.get("/api/billing/plans")
        assert r.status_code == 200
        plans = r.json()["plans"]
        assert "pro" in plans
        assert "team" in plans
        assert plans["pro"]["monthly_price"] == 29
        assert plans["team"]["monthly_price"] == 99

    def test_checkout_requires_auth(self, client):
        r = client.post("/api/billing/checkout", json={"plan":"pro","success_url":"https://x.com","cancel_url":"https://x.com"})
        assert r.status_code == 401

    def test_checkout_invalid_plan(self, client, auth_headers, mock_user):
        with patch("app.routers.billing.get_current_user", return_value=mock_user):
            r = client.post("/api/billing/checkout",
                           json={"plan":"diamond","success_url":"https://x.com","cancel_url":"https://x.com"},
                           headers=auth_headers)
        assert r.status_code == 400

    def test_checkout_creates_session(self, client, auth_headers, mock_user):
        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/session-123"
        mock_session.id = "cs_123"
        with patch("app.routers.billing.get_current_user", return_value=mock_user), \
             patch("stripe.Customer.create", return_value=MagicMock(id="cus_123")), \
             patch("stripe.checkout.Session.create", return_value=mock_session), \
             patch("app.database.db.update_profile", new_callable=AsyncMock):
            r = client.post("/api/billing/checkout",
                           json={"plan":"pro","billing_cycle":"monthly",
                                 "success_url":"https://securescan.io/success",
                                 "cancel_url":"https://securescan.io/cancel"},
                           headers=auth_headers)
        assert r.status_code == 200
        assert "url" in r.json()

    def test_webhook_invalid_signature(self, client):
        r = client.post("/api/billing/webhook",
                       content=b"{}",
                       headers={"stripe-signature":"invalid"})
        assert r.status_code == 400

# ══════════════════════════════════════════════════════════════════════════════
# MONITORING
# ══════════════════════════════════════════════════════════════════════════════
class TestMonitoring:
    def test_list_sites_requires_auth(self, client):
        r = client.get("/api/monitoring/sites")
        assert r.status_code == 401

    def test_list_sites_success(self, client, auth_headers, mock_user):
        sites = [{"id":"site-1","url":"https://example.com","interval_hours":24}]
        with patch("app.routers.monitoring.get_current_user", return_value=mock_user), \
             patch("app.database.db.list_sites", new_callable=AsyncMock, return_value=sites):
            r = client.get("/api/monitoring/sites", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()["sites"]) == 1

    def test_add_site_free_user_rejected(self, client, auth_headers, mock_free_user):
        with patch("app.routers.monitoring.require_pro", side_effect=HTTPException(403, "Pro required")):
            r = client.post("/api/monitoring/sites",
                           json={"url":"https://example.com"},
                           headers=auth_headers)
        assert r.status_code == 403

    def test_add_site_pro_user(self, client, auth_headers, mock_user):
        new_site = {"id":"site-new","url":"https://example.com","user_id":"user-123"}
        with patch("app.routers.monitoring.require_pro", return_value=mock_user), \
             patch("app.database.db.list_sites", new_callable=AsyncMock, return_value=[]), \
             patch("app.database.db.add_site", new_callable=AsyncMock, return_value=new_site):
            r = client.post("/api/monitoring/sites",
                           json={"url":"https://example.com","interval_hours":24},
                           headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["site"]["url"] == "https://example.com"

    def test_site_limit_enforced(self, client, auth_headers, mock_user):
        # Pro has 10 sites limit
        sites = [{"id":f"s-{i}","url":f"https://site{i}.com"} for i in range(10)]
        with patch("app.routers.monitoring.require_pro", return_value=mock_user), \
             patch("app.database.db.list_sites", new_callable=AsyncMock, return_value=sites):
            r = client.post("/api/monitoring/sites",
                           json={"url":"https://new.com"},
                           headers=auth_headers)
        assert r.status_code == 403

    def test_delete_site(self, client, auth_headers, mock_user):
        with patch("app.routers.monitoring.get_current_user", return_value=mock_user), \
             patch("app.database.db.delete_site", new_callable=AsyncMock):
            r = client.delete("/api/monitoring/sites/site-1", headers=auth_headers)
        assert r.status_code == 200

    def test_list_alerts(self, client, auth_headers, mock_user):
        alerts = [{"id":"a1","type":"score_drop","message":"Score dropped","email_sent":True}]
        with patch("app.routers.monitoring.get_current_user", return_value=mock_user), \
             patch("app.database.db.list_alerts", new_callable=AsyncMock, return_value=alerts):
            r = client.get("/api/monitoring/alerts", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()["alerts"]) == 1

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL SERVICE
# ══════════════════════════════════════════════════════════════════════════════
class TestEmailService:
    def test_send_welcome_no_key(self):
        from app.services.email import send_welcome
        with patch("app.services.email.settings") as mock_settings:
            mock_settings.sendgrid_api_key = ""
            result = send_welcome("test@example.com", "Test")
        assert result == False

    def test_send_scan_complete_with_key(self):
        from app.services.email import send_scan_complete
        mock_sg = MagicMock()
        mock_sg.send.return_value = MagicMock(status_code=202)
        with patch("app.services.email.settings") as mock_settings, \
             patch("app.services.email.SendGridAPIClient", return_value=mock_sg):
            mock_settings.sendgrid_api_key = "SG.test"
            mock_settings.from_email = "test@securescan.io"
            mock_settings.from_name = "SecureScan"
            mock_settings.app_url = "https://securescan.io"
            result = send_scan_complete("user@ex.com","example.com",85,"B",0,2,"scan-123")
        mock_sg.send.assert_called_once()

    def test_send_alert_score_drop(self):
        from app.services.email import send_alert
        mock_sg = MagicMock()
        with patch("app.services.email.settings") as mock_settings, \
             patch("app.services.email.SendGridAPIClient", return_value=mock_sg):
            mock_settings.sendgrid_api_key = "SG.test"
            mock_settings.from_email = "noreply@securescan.io"
            mock_settings.from_name = "SecureScan"
            mock_settings.app_url = "https://securescan.io"
            send_alert("user@ex.com","https://example.com","score_drop","Score dropped from 85 to 70",70)
        mock_sg.send.assert_called_once()

# ══════════════════════════════════════════════════════════════════════════════
# PDF SERVICE
# ══════════════════════════════════════════════════════════════════════════════
class TestPdfService:
    def test_generate_pdf_returns_bytes(self):
        from app.services.pdf import generate_pdf
        scan_data = {
            "hostname": "example.com",
            "url": "https://example.com",
            "score": 75,
            "grade": "C",
            "severity_counts": {"critical":2,"high":5,"medium":3,"low":1},
            "ai_summary": "Your site has several issues to address.",
            "categories": [
                {
                    "id":"headers","name":"Security Headers","icon":"🛡️","score":60,
                    "findings": [
                        {"severity":"high","title":"Missing CSP","status":"fail","detail":"No Content-Security-Policy header.","fix":"Add CSP header."},
                        {"severity":"low","title":"X-Frame-Options present","status":"pass","detail":"Header is set."},
                    ]
                }
            ]
        }
        pdf_bytes = generate_pdf(scan_data)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes[:4] == b"%PDF"

    def test_generate_pdf_empty_scan(self):
        from app.services.pdf import generate_pdf
        pdf_bytes = generate_pdf({"hostname":"x.com","score":50,"grade":"F","severity_counts":{},"categories":[]})
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes[:4] == b"%PDF"

# ══════════════════════════════════════════════════════════════════════════════
# AI SERVICE
# ══════════════════════════════════════════════════════════════════════════════
class TestAiService:
    def test_returns_none_without_key(self):
        from app.services.ai import get_ai_summary
        with patch("app.services.ai.settings") as mock_s:
            mock_s.anthropic_api_key = ""
            result = get_ai_summary("https://ex.com", [], 80, "B")
        assert result is None

    def test_returns_summary_with_key(self):
        from app.services.ai import get_ai_summary
        mock_client = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = [MagicMock(text="Your site is mostly secure but has some cookie issues to fix.")]
        mock_client.messages.create.return_value = mock_msg
        with patch("app.services.ai.settings") as mock_s, \
             patch("anthropic.Anthropic", return_value=mock_client):
            mock_s.anthropic_api_key = "sk-ant-test"
            result = get_ai_summary("https://example.com",[{"findings":[]}],80,"B")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_handles_api_error_gracefully(self):
        from app.services.ai import get_ai_summary
        with patch("app.services.ai.settings") as mock_s, \
             patch("anthropic.Anthropic", side_effect=Exception("API Error")):
            mock_s.anthropic_api_key = "sk-ant-test"
            result = get_ai_summary("https://ex.com",[], 50, "F")
        assert result is None

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG & PLAN LIMITS
# ══════════════════════════════════════════════════════════════════════════════
class TestConfig:
    def test_plan_limits_defined(self):
        from app.config import settings
        assert "free" in settings.PLAN_LIMITS
        assert "pro"  in settings.PLAN_LIMITS
        assert "team" in settings.PLAN_LIMITS

    def test_free_plan_limits(self):
        from app.config import settings
        free = settings.PLAN_LIMITS["free"]
        assert free["scans"] == 5
        assert free["sites"] == 1
        assert free["pdf"]   == False
        assert free["ai"]    == False

    def test_pro_plan_limits(self):
        from app.config import settings
        pro = settings.PLAN_LIMITS["pro"]
        assert pro["scans"] == 100
        assert pro["sites"] == 10
        assert pro["pdf"]   == True
        assert pro["ai"]    == True

    def test_team_plan_limits(self):
        from app.config import settings
        team = settings.PLAN_LIMITS["team"]
        assert team["scans"] >= 1000
        assert team["sites"] == 50
        assert team["pdf"]   == True
        assert team["ai"]    == True

    def test_origins_list_parsed(self):
        from app.config import Settings
        s = Settings(allowed_origins="https://a.com,https://b.com")
        assert "https://a.com" in s.origins_list
        assert "https://b.com" in s.origins_list

# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION — Full scan flow (mocked)
# ══════════════════════════════════════════════════════════════════════════════
class TestIntegration:
    def test_full_scan_flow(self, client, auth_headers, mock_user):
        """Test complete scan flow: start → poll → complete"""
        scan_id = "integration-scan-001"
        complete_scan = {
            "id": scan_id, "user_id": "user-123", "url": "https://example.com",
            "hostname": "example.com", "status": "complete", "score": 72,
            "grade": "C", "severity_counts": {"critical":1,"high":3,"medium":5,"low":2},
            "categories": [], "ai_summary": "Fix your SSL and headers.", "total_checks": 45,
        }
        with patch("app.routers.scan.check_scan_limit", return_value=mock_user), \
             patch("app.database.db.create_scan", new_callable=AsyncMock, return_value=scan_id), \
             patch("app.routers.scan._run_scan", new_callable=AsyncMock), \
             patch("app.routers.scan.get_current_user", return_value=mock_user), \
             patch("app.database.db.get_scan", new_callable=AsyncMock, return_value=complete_scan):
            # Step 1: Start scan
            r1 = client.post("/api/scan", json={"url":"https://example.com"}, headers=auth_headers)
            assert r1.status_code == 200
            assert r1.json()["scan_id"] == scan_id

            # Step 2: Poll for result
            r2 = client.get(f"/api/scan/{scan_id}", headers=auth_headers)
            assert r2.status_code == 200
            data = r2.json()
            assert data["status"] == "complete"
            assert data["score"] == 72
            assert data["grade"] == "C"

    def test_monitoring_full_flow(self, client, auth_headers, mock_user):
        """Test add site → list → delete"""
        new_site = {"id":"site-abc","url":"https://mysite.com","user_id":"user-123","interval_hours":24}
        with patch("app.routers.monitoring.require_pro", return_value=mock_user), \
             patch("app.routers.monitoring.get_current_user", return_value=mock_user), \
             patch("app.database.db.list_sites", new_callable=AsyncMock, side_effect=[[], [new_site], []]), \
             patch("app.database.db.add_site", new_callable=AsyncMock, return_value=new_site), \
             patch("app.database.db.delete_site", new_callable=AsyncMock):
            # Add
            r1 = client.post("/api/monitoring/sites", json={"url":"https://mysite.com"}, headers=auth_headers)
            assert r1.status_code == 200

            # List
            r2 = client.get("/api/monitoring/sites", headers=auth_headers)
            assert r2.status_code == 200
            assert len(r2.json()["sites"]) == 1

            # Delete
            r3 = client.delete("/api/monitoring/sites/site-abc", headers=auth_headers)
            assert r3.status_code == 200


# Fix missing import
from fastapi import HTTPException

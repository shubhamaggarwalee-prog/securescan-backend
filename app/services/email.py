from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from app.config import settings

def _send(to_email: str, subject: str, html: str):
    if not settings.sendgrid_api_key:
        print(f"[EMAIL SKIP] No SendGrid key. Would send: {subject} → {to_email}")
        return False
    try:
        sg = SendGridAPIClient(settings.sendgrid_api_key)
        msg = Mail(
            from_email=(settings.from_email, settings.from_name),
            to_emails=to_email,
            subject=subject,
            html_content=html,
        )
        sg.send(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def _base_template(content: str, preview: str = "") -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{{margin:0;padding:0;background:#f0f4f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}}
  .wrap{{max-width:600px;margin:0 auto;padding:32px 16px}}
  .card{{background:#fff;border-radius:16px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,.08)}}
  .logo{{font-family:'Courier New',monospace;font-weight:800;font-size:20px;color:#0077cc;letter-spacing:1px;margin-bottom:24px}}
  .logo span{{color:#0f1923}}
  h2{{color:#0f1923;font-size:20px;margin:0 0 12px}}
  p{{color:#3a4a5c;font-size:14px;line-height:1.7;margin:0 0 16px}}
  .score-badge{{display:inline-block;padding:12px 28px;border-radius:99px;font-weight:900;font-size:28px;font-family:'Courier New',monospace;margin:16px 0}}
  .btn{{display:inline-block;background:linear-gradient(90deg,#005fa3,#0077cc);color:#fff;padding:13px 28px;border-radius:10px;text-decoration:none;font-weight:700;font-size:14px;margin:8px 0}}
  .issue{{background:#fff0f3;border-left:3px solid #d9002e;border-radius:6px;padding:10px 14px;margin:6px 0;font-size:13px;color:#3a4a5c}}
  .footer{{text-align:center;color:#7a8fa6;font-size:11px;margin-top:24px;line-height:1.6}}
  .divider{{border:none;border-top:1px solid #e4eaf0;margin:20px 0}}
</style>
</head>
<body>
<div class="wrap">
<div class="card">
<div class="logo">⚡ <span>SECURE</span>SCAN</div>
{content}
</div>
<div class="footer">
  SecureScan · <a href="{settings.app_url}/unsubscribe" style="color:#7a8fa6">Unsubscribe</a><br>
  You're receiving this because you enabled monitoring alerts.
</div>
</div>
</body></html>"""

def send_welcome(to_email: str, name: str = ""):
    greeting = f"Hi {name}," if name else "Welcome,"
    html = _base_template(f"""
<h2>Welcome to SecureScan! 🎉</h2>
<p>{greeting}</p>
<p>Your account is ready. Start scanning websites for security vulnerabilities — get a full report in under 60 seconds.</p>
<p>Your free plan includes <strong>5 scans per month</strong>. Upgrade to Pro for 100 scans, PDF reports, and AI-powered remediation.</p>
<a href="{settings.app_url}" class="btn">Start Scanning →</a>
<hr class="divider">
<p style="font-size:12px;color:#7a8fa6">Need help? Reply to this email anytime.</p>
""")
    return _send(to_email, "Welcome to SecureScan ⚡", html)

def send_scan_complete(to_email: str, hostname: str, score: int, grade: str, critical: int, high: int, scan_id: str):
    grade_colors = {"A":"#007a33","B":"#2e7d32","C":"#8a6000","D":"#c44b00","F":"#d9002e"}
    color = grade_colors.get(grade, "#888")
    issues_html = ""
    if critical > 0:
        issues_html += f'<div class="issue">🚨 {critical} critical issue{"s" if critical>1 else ""} require immediate attention</div>'
    if high > 0:
        issues_html += f'<div class="issue" style="background:#fff5ee;border-color:#c44b00">⚠️ {high} high severity issue{"s" if high>1 else ""} found</div>'
    html = _base_template(f"""
<h2>Scan Complete: {hostname}</h2>
<p>Your security scan finished. Here's the summary:</p>
<div style="text-align:center;margin:20px 0">
  <div class="score-badge" style="background:{color}20;color:{color};border:2px solid {color}">{grade} — {score}/100</div>
</div>
{issues_html}
<p>View your full report with detailed findings and fix instructions:</p>
<a href="{settings.app_url}/scan/{scan_id}" class="btn">View Full Report →</a>
""")
    return _send(to_email, f"SecureScan: {hostname} scored {score}/100 (Grade {grade})", html)

def send_alert(to_email: str, site_url: str, alert_type: str, message: str, score: int = None):
    type_config = {
        "score_drop":        ("📉 Score Drop Alert", "Your site's security score dropped significantly."),
        "critical_finding":  ("🚨 Critical Finding", "A critical security issue was found on your site."),
        "cert_expiry":       ("🔐 Certificate Expiring", "Your SSL certificate is expiring soon."),
        "scan_complete":     ("✅ Monitoring Scan Complete", "Your scheduled security scan finished."),
    }
    subject_suffix, intro = type_config.get(alert_type, ("⚠️ Security Alert", "An alert was triggered for your site."))
    score_line = f"<p><strong>Current Score:</strong> {score}/100</p>" if score else ""
    html = _base_template(f"""
<h2>{subject_suffix}</h2>
<p><strong>Site:</strong> {site_url}</p>
{score_line}
<p>{intro}</p>
<p style="background:#fff0f3;border-left:3px solid #d9002e;border-radius:6px;padding:12px 16px;color:#3a4a5c">{message}</p>
<a href="{settings.app_url}/monitoring" class="btn">View Monitoring Dashboard →</a>
""")
    return _send(to_email, f"SecureScan Alert: {subject_suffix} — {site_url}", html)

def send_password_reset(to_email: str, reset_link: str):
    html = _base_template(f"""
<h2>Reset Your Password</h2>
<p>We received a request to reset the password for your SecureScan account.</p>
<a href="{reset_link}" class="btn">Reset Password →</a>
<p style="font-size:12px;color:#7a8fa6;margin-top:16px">This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
""")
    return _send(to_email, "Reset your SecureScan password", html)

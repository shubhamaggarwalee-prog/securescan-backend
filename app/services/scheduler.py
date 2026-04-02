from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime, timezone
import asyncio
from app.database import db
from app.services.scanner import run_all_scanners
from app.services.email import send_alert
from app.services.ai import get_ai_summary

scheduler = AsyncIOScheduler()

async def run_monitoring_job():
    """Run all due monitoring scans."""
    print(f"[MONITOR] Running monitoring job at {datetime.now(timezone.utc).isoformat()}")
    sites = await db.get_all_active_sites()
    for site in sites:
        try:
            last = site.get("last_scanned_at")
            interval_h = site.get("interval_hours", 24)
            if last:
                from datetime import timedelta
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                due_at  = last_dt + timedelta(hours=interval_h)
                if datetime.now(timezone.utc) < due_at:
                    continue
            await scan_monitored_site(site)
        except Exception as e:
            print(f"[MONITOR] Error for {site.get('url')}: {e}")

async def scan_monitored_site(site: dict):
    from urllib.parse import urlparse
    url      = site["url"]
    hostname = urlparse(url).hostname
    if not hostname:
        return

    print(f"[MONITOR] Scanning {url}")
    loop   = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, run_all_scanners, hostname)

    score     = result["score"]
    grade     = result["grade"]
    prev_score = site.get("last_score")

    # Update site record
    await db.update_site(site["id"], {
        "last_scanned_at": datetime.now(timezone.utc).isoformat(),
        "last_score": score,
        "last_grade": grade,
    })

    # Get user profile for email
    profile = await db.get_profile(site["user_id"])
    if not profile:
        return

    plan = profile.get("plan","free")
    if plan not in ("pro","team"):
        return  # Alerts are pro+ feature

    # Alert: score drop
    if prev_score and score < prev_score - 10:
        msg = f"Security score dropped from {prev_score} to {score} (Grade {grade})."
        await db.create_alert(site["user_id"], site["id"], "score_drop", msg, True)
        if profile.get("notification_email"):
            send_alert(profile["email"], url, "score_drop", msg, score)

    # Alert: critical findings
    crit = result["severity_counts"].get("critical", 0)
    if crit > 0:
        msg = f"{crit} critical security issue{'s' if crit>1 else ''} found."
        await db.create_alert(site["user_id"], site["id"], "critical_finding", msg, True)
        if profile.get("notification_email"):
            send_alert(profile["email"], url, "critical_finding", msg, score)

    # Alert: cert expiry (check if SSL category has expiry warning)
    for cat in result.get("categories",[]):
        if cat.get("id") == "ssl":
            for f in cat.get("findings",[]):
                if "expires" in f.get("title","").lower() and f.get("status") == "fail":
                    msg = f["title"]
                    await db.create_alert(site["user_id"], site["id"], "cert_expiry", msg, True)
                    if profile.get("notification_email"):
                        send_alert(profile["email"], url, "cert_expiry", msg, score)
                    break

async def reset_monthly_scans():
    """Reset scan counts at start of each month."""
    await db.client.rpc("reset_monthly_scans").execute()
    print("[SCHEDULER] Monthly scan counts reset")

def start_scheduler():
    scheduler.add_job(run_monitoring_job, IntervalTrigger(minutes=15), id="monitoring", replace_existing=True)
    scheduler.add_job(reset_monthly_scans, "cron", day=1, hour=0, minute=0, id="monthly_reset", replace_existing=True)
    scheduler.start()
    print("[SCHEDULER] Started — monitoring every 15 minutes")

def stop_scheduler():
    scheduler.shutdown()

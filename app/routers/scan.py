from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import Response
from pydantic import BaseModel, HttpUrl
from app.auth import get_current_user, check_scan_limit
from app.database import db
from app.services.scanner import run_all_scanners
from app.services.ai import get_ai_summary
from app.services.pdf import generate_pdf
from app.services.email import send_scan_complete
import asyncio, time

router = APIRouter(prefix="/api", tags=["scans"])

class ScanRequest(BaseModel):
    url: str
    include_ai: bool = True

async def _run_scan(scan_id: str, url: str, hostname: str, user_id: str,
                    user_email: str, include_ai: bool, plan: str):
    start = time.time()
    try:
        await db.update_scan(scan_id, {"status": "running"})
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_all_scanners, hostname)

        ai_summary = None
        from app.config import settings
        if include_ai and settings.PLAN_LIMITS.get(plan,{}).get("ai"):
            ai_summary = get_ai_summary(url, result["categories"], result["score"], result["grade"])

        duration_ms = int((time.time() - start) * 1000)
        await db.update_scan(scan_id, {
            "status":          "complete",
            "score":           result["score"],
            "grade":           result["grade"],
            "severity_counts": result["severity_counts"],
            "categories":      result["categories"],
            "ai_summary":      ai_summary,
            "total_checks":    result["total_checks"],
            "scan_duration_ms": duration_ms,
        })
        await db.increment_scan_count(user_id)

        # Email notification (non-blocking)
        sc = result["severity_counts"]
        try:
            send_scan_complete(user_email, hostname, result["score"], result["grade"],
                               sc.get("critical",0), sc.get("high",0), scan_id)
        except Exception:
            pass

    except Exception as e:
        await db.update_scan(scan_id, {"status": "error", "error_message": str(e)})

@router.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks,
                     user=Depends(check_scan_limit)):
    url = req.url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    from urllib.parse import urlparse
    hostname = urlparse(url).hostname
    if not hostname:
        raise HTTPException(400, "Invalid URL")

    scan_id = await db.create_scan(user["id"], url, hostname)
    background_tasks.add_task(
        _run_scan, scan_id, url, hostname,
        user["id"], user["email"], req.include_ai, user.get("plan","free")
    )
    return {"scan_id": scan_id, "status": "queued"}

@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["user_id"] != user["id"]:
        raise HTTPException(403, "Access denied")
    return scan

@router.get("/scans")
async def list_scans(limit: int = 20, user=Depends(get_current_user)):
    scans = await db.list_scans(user["id"], limit=min(limit, 100))
    return {"scans": scans, "total": len(scans)}

@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    await db.delete_scan(scan_id, user["id"])
    return {"deleted": True}

@router.get("/scan/{scan_id}/pdf")
async def download_pdf(scan_id: str, user=Depends(get_current_user)):
    from app.config import settings
    if not settings.PLAN_LIMITS.get(user.get("plan","free"),{}).get("pdf"):
        raise HTTPException(403, "PDF reports require Pro or Team plan")
    scan = await db.get_scan(scan_id)
    if not scan or scan["user_id"] != user["id"]:
        raise HTTPException(404, "Scan not found")
    if scan["status"] != "complete":
        raise HTTPException(400, "Scan not complete yet")
    pdf_bytes = generate_pdf(scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="securescan-{scan["hostname"]}.pdf"'}
    )

@router.get("/me")
async def get_me(user=Depends(get_current_user)):
    from app.config import settings
    plan  = user.get("plan","free")
    limit = settings.PLAN_LIMITS[plan]["scans"]
    used  = user.get("scans_this_month", 0)
    return {
        **user,
        "scan_limit":      limit,
        "scans_remaining": max(0, limit - used),
        "features":        settings.PLAN_LIMITS[plan],
    }

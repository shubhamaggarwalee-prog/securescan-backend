from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.auth import get_current_user, require_pro
from app.database import db
from app.config import settings

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])

class AddSiteRequest(BaseModel):
    url: str
    interval_hours: int = 24

@router.get("/sites")
async def list_sites(user=Depends(get_current_user)):
    sites = await db.list_sites(user["id"])
    return {"sites": sites}

@router.post("/sites")
async def add_site(req: AddSiteRequest, user=Depends(require_pro)):
    plan  = user.get("plan","free")
    limit = settings.PLAN_LIMITS[plan]["sites"]
    sites = await db.list_sites(user["id"])
    if len(sites) >= limit:
        raise HTTPException(403, f"Site limit reached ({limit} on {plan} plan). Upgrade to add more.")
    url = req.url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    from urllib.parse import urlparse
    if not urlparse(url).hostname:
        raise HTTPException(400, "Invalid URL")
    # Check for duplicate
    if any(s["url"] == url for s in sites):
        raise HTTPException(409, "Site already being monitored")
    site = await db.add_site(user["id"], url, req.interval_hours)
    return {"site": site}

@router.delete("/sites/{site_id}")
async def delete_site(site_id: str, user=Depends(get_current_user)):
    await db.delete_site(site_id, user["id"])
    return {"deleted": True}

@router.patch("/sites/{site_id}")
async def update_site(site_id: str, req: dict, user=Depends(require_pro)):
    allowed = {"interval_hours","active","score_threshold"}
    updates = {k: v for k, v in req.items() if k in allowed}
    if not updates:
        raise HTTPException(400, "No valid fields to update")
    await db.update_site(site_id, updates)
    return {"updated": True}

@router.get("/alerts")
async def list_alerts(limit: int = 50, user=Depends(get_current_user)):
    alerts = await db.list_alerts(user["id"], limit=min(limit,200))
    return {"alerts": alerts}

@router.patch("/alerts/{alert_id}/read")
async def mark_alert_read(alert_id: str, user=Depends(get_current_user)):
    db.client.table("alerts").update({"read": True}).eq("id", alert_id).eq("user_id", user["id"]).execute()
    return {"updated": True}

@router.post("/alerts/read-all")
async def mark_all_alerts_read(user=Depends(get_current_user)):
    db.client.table("alerts").update({"read": True}).eq("user_id", user["id"]).execute()
    return {"updated": True}

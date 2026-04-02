from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from app.config import settings
from app.database import db

bearer = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    profile = await db.get_profile(user_id)
    if not profile:
        # Auto-create profile on first login
        profile = await db.create_profile(user_id, payload.get("email", ""))
    return profile

async def require_pro(user=Depends(get_current_user)):
    if user.get("plan") not in ("pro", "team"):
        raise HTTPException(status_code=403, detail="Pro or Team plan required")
    return user

async def require_team(user=Depends(get_current_user)):
    if user.get("plan") != "team":
        raise HTTPException(status_code=403, detail="Team plan required")
    return user

async def check_scan_limit(user=Depends(get_current_user)):
    from app.config import settings as s
    plan   = user.get("plan", "free")
    limit  = s.PLAN_LIMITS[plan]["scans"]
    used   = user.get("scans_this_month", 0)
    if used >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Monthly scan limit reached ({limit} scans on {plan} plan). Upgrade to scan more."
        )
    return user

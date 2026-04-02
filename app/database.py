from supabase import create_client, Client
from app.config import settings
from datetime import datetime, timezone
import uuid

class Database:
    def __init__(self):
        self._client: Client = None

    @property
    def client(self) -> Client:
        if not self._client:
            self._client = create_client(settings.supabase_url, settings.supabase_service_key)
        return self._client

    # ── Profiles ──────────────────────────────────────────────────────────────
    async def get_profile(self, user_id: str):
        r = self.client.table("profiles").select("*").eq("id", user_id).single().execute()
        return r.data

    async def create_profile(self, user_id: str, email: str):
        data = {"id": user_id, "email": email, "plan": "free",
                "scans_this_month": 0, "scan_limit": 5,
                "created_at": datetime.now(timezone.utc).isoformat()}
        r = self.client.table("profiles").insert(data).execute()
        return r.data[0] if r.data else data

    async def update_profile(self, user_id: str, updates: dict):
        r = self.client.table("profiles").update(updates).eq("id", user_id).execute()
        return r.data[0] if r.data else None

    async def increment_scan_count(self, user_id: str):
        profile = await self.get_profile(user_id)
        new_count = (profile.get("scans_this_month") or 0) + 1
        await self.update_profile(user_id, {"scans_this_month": new_count})

    # ── Scans ─────────────────────────────────────────────────────────────────
    async def create_scan(self, user_id: str, url: str, hostname: str):
        scan_id = str(uuid.uuid4())
        data = {"id": scan_id, "user_id": user_id, "url": url,
                "hostname": hostname, "status": "queued",
                "created_at": datetime.now(timezone.utc).isoformat()}
        self.client.table("scans").insert(data).execute()
        return scan_id

    async def update_scan(self, scan_id: str, updates: dict):
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.client.table("scans").update(updates).eq("id", scan_id).execute()

    async def get_scan(self, scan_id: str):
        r = self.client.table("scans").select("*").eq("id", scan_id).single().execute()
        return r.data

    async def list_scans(self, user_id: str, limit: int = 20):
        r = (self.client.table("scans").select("*")
             .eq("user_id", user_id)
             .eq("status", "complete")
             .order("created_at", desc=True)
             .limit(limit).execute())
        return r.data or []

    async def delete_scan(self, scan_id: str, user_id: str):
        self.client.table("scans").delete().eq("id", scan_id).eq("user_id", user_id).execute()

    # ── Monitored Sites ───────────────────────────────────────────────────────
    async def list_sites(self, user_id: str):
        r = self.client.table("monitored_sites").select("*").eq("user_id", user_id).execute()
        return r.data or []

    async def add_site(self, user_id: str, url: str, interval_hours: int = 24):
        data = {"id": str(uuid.uuid4()), "user_id": user_id, "url": url,
                "interval_hours": interval_hours, "active": True,
                "created_at": datetime.now(timezone.utc).isoformat()}
        r = self.client.table("monitored_sites").insert(data).execute()
        return r.data[0] if r.data else None

    async def delete_site(self, site_id: str, user_id: str):
        self.client.table("monitored_sites").delete().eq("id", site_id).eq("user_id", user_id).execute()

    async def get_all_active_sites(self):
        r = self.client.table("monitored_sites").select("*").eq("active", True).execute()
        return r.data or []

    async def update_site(self, site_id: str, updates: dict):
        self.client.table("monitored_sites").update(updates).eq("id", site_id).execute()

    # ── Alerts ────────────────────────────────────────────────────────────────
    async def create_alert(self, user_id: str, site_id: str, alert_type: str, message: str, email_sent: bool = False):
        data = {"id": str(uuid.uuid4()), "user_id": user_id, "site_id": site_id,
                "type": alert_type, "message": message, "email_sent": email_sent,
                "sent_at": datetime.now(timezone.utc).isoformat()}
        self.client.table("alerts").insert(data).execute()

    async def list_alerts(self, user_id: str, limit: int = 50):
        r = (self.client.table("alerts").select("*")
             .eq("user_id", user_id).order("sent_at", desc=True).limit(limit).execute())
        return r.data or []

    # ── API Keys ──────────────────────────────────────────────────────────────
    async def create_api_key(self, user_id: str, name: str, key_hash: str):
        data = {"id": str(uuid.uuid4()), "user_id": user_id, "name": name,
                "key_hash": key_hash, "active": True,
                "created_at": datetime.now(timezone.utc).isoformat()}
        r = self.client.table("api_keys").insert(data).execute()
        return r.data[0] if r.data else None

    async def list_api_keys(self, user_id: str):
        r = self.client.table("api_keys").select("id,name,active,created_at,last_used_at").eq("user_id", user_id).execute()
        return r.data or []

    async def delete_api_key(self, key_id: str, user_id: str):
        self.client.table("api_keys").delete().eq("id", key_id).eq("user_id", user_id).execute()

db = Database()

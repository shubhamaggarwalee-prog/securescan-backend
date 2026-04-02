from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # Supabase
    supabase_url: str = ""
    supabase_service_key: str = ""
    supabase_jwt_secret: str = ""

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_pro_monthly_price_id: str = ""
    stripe_pro_yearly_price_id: str = ""
    stripe_team_monthly_price_id: str = ""
    stripe_team_yearly_price_id: str = ""

    # Anthropic
    anthropic_api_key: str = ""

    # SendGrid
    sendgrid_api_key: str = ""
    from_email: str = "noreply@securescan.io"
    from_name: str = "SecureScan"

    # App
    app_url: str = "https://securescan.io"
    allowed_origins: str = "https://securescan.io"
    secret_key: str = "dev-secret-key-change-in-production"
    environment: str = "development"

    class Config:
        env_file = ".env"
        extra = "ignore"

    @property
    def is_production(self):
        return self.environment == "production"

    @property
    def origins_list(self):
        return [o.strip() for o in self.allowed_origins.split(",")]

    # Plan limits
    PLAN_LIMITS = {
        "free":  {"scans": 5,   "sites": 1,  "pdf": False, "ai": False, "alerts": False},
        "pro":   {"scans": 100, "sites": 10, "pdf": True,  "ai": True,  "alerts": True},
        "team":  {"scans": 9999,"sites": 50, "pdf": True,  "ai": True,  "alerts": True},
    }

@lru_cache()
def get_settings():
    return Settings()

settings = get_settings()

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.auth import get_current_user
from app.database import db
from app.config import settings
import stripe

stripe.api_key = settings.stripe_secret_key
router = APIRouter(prefix="/api/billing", tags=["billing"])

PLANS = {
    "pro": {
        "name": "Pro",
        "monthly_price": 29,
        "yearly_price": 249,
        "scans": 100,
        "sites": 10,
        "features": ["100 scans/month","10 monitored sites","PDF reports","AI summaries","Email alerts","Priority support"],
    },
    "team": {
        "name": "Team",
        "monthly_price": 99,
        "yearly_price": 849,
        "scans": 9999,
        "sites": 50,
        "features": ["Unlimited scans","50 monitored sites","PDF reports","AI summaries","Slack alerts","CI/CD webhooks","API access","Team management"],
    },
}

class CheckoutRequest(BaseModel):
    plan: str
    billing_cycle: str = "monthly"  # monthly | yearly
    success_url: str
    cancel_url: str

@router.get("/plans")
async def get_plans():
    return {"plans": PLANS}

@router.post("/checkout")
async def create_checkout(req: CheckoutRequest, user=Depends(get_current_user)):
    if req.plan not in ("pro","team"):
        raise HTTPException(400, "Invalid plan")

    price_map = {
        ("pro",  "monthly"): settings.stripe_pro_monthly_price_id,
        ("pro",  "yearly"):  settings.stripe_pro_yearly_price_id,
        ("team", "monthly"): settings.stripe_team_monthly_price_id,
        ("team", "yearly"):  settings.stripe_team_yearly_price_id,
    }
    price_id = price_map.get((req.plan, req.billing_cycle))
    if not price_id:
        raise HTTPException(400, "Invalid plan/cycle combination")

    # Get or create Stripe customer
    customer_id = user.get("stripe_customer_id")
    if not customer_id:
        customer = stripe.Customer.create(
            email=user["email"],
            metadata={"user_id": user["id"], "plan": req.plan}
        )
        customer_id = customer.id
        await db.update_profile(user["id"], {"stripe_customer_id": customer_id})

    session = stripe.checkout.Session.create(
        customer=customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=req.success_url + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=req.cancel_url,
        metadata={"user_id": user["id"], "plan": req.plan, "cycle": req.billing_cycle},
        subscription_data={"metadata": {"user_id": user["id"], "plan": req.plan}},
        allow_promotion_codes=True,
    )
    return {"url": session.url, "session_id": session.id}

@router.post("/portal")
async def billing_portal(user=Depends(get_current_user)):
    customer_id = user.get("stripe_customer_id")
    if not customer_id:
        raise HTTPException(400, "No billing account found")
    session = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{settings.app_url}/settings",
    )
    return {"url": session.url}

@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig     = request.headers.get("stripe-signature","")
    try:
        event = stripe.Webhook.construct_event(payload, sig, settings.stripe_webhook_secret)
    except Exception:
        raise HTTPException(400, "Invalid webhook signature")

    # Idempotency check
    existing = db.client.table("webhook_events").select("id").eq("id", event["id"]).execute()
    if existing.data:
        return {"status": "already_processed"}
    db.client.table("webhook_events").insert({"id": event["id"], "type": event["type"]}).execute()

    et = event["type"]
    data = event["data"]["object"]

    if et == "checkout.session.completed":
        user_id = data["metadata"].get("user_id")
        plan    = data["metadata"].get("plan","pro")
        cycle   = data["metadata"].get("cycle","monthly")
        sub_id  = data.get("subscription")
        scan_limit = {"pro":100,"team":9999}.get(plan,5)
        if user_id:
            await db.update_profile(user_id, {
                "plan": plan,
                "stripe_subscription_id": sub_id,
                "subscription_status": "active",
                "billing_cycle": cycle,
                "scan_limit": scan_limit,
            })

    elif et in ("customer.subscription.updated","customer.subscription.deleted"):
        sub_id = data["id"]
        status = data["status"]
        profile = db.client.table("profiles").select("id").eq("stripe_subscription_id", sub_id).execute()
        if profile.data:
            user_id = profile.data[0]["id"]
            if et == "customer.subscription.deleted" or status in ("canceled","unpaid"):
                await db.update_profile(user_id, {"plan":"free","subscription_status":"inactive","scan_limit":5})
            else:
                plan = data.get("metadata",{}).get("plan","pro")
                await db.update_profile(user_id, {"subscription_status": status,
                                                   "plan": plan if status=="active" else "free"})

    elif et == "invoice.payment_failed":
        customer_id = data.get("customer")
        profile = db.client.table("profiles").select("id").eq("stripe_customer_id", customer_id).execute()
        if profile.data:
            await db.update_profile(profile.data[0]["id"], {"subscription_status":"past_due"})

    return {"status": "ok"}

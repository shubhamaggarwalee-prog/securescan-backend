# SecureScan — Railway Deployment Guide
# ════════════════════════════════════════════════════════
# Estimated time: 15 minutes
# Cost: ~$5/month (Railway Starter plan)
# No sleep. No cold starts. Always on.
# ════════════════════════════════════════════════════════


## BEFORE YOU START — 3 things to have ready

1. A GitHub account (free) — railway.app deploys from GitHub
2. Your Supabase project created at supabase.com (free)
3. Your Stripe account at stripe.com (free until you earn revenue)


## STEP 1 — Push code to GitHub

1. Go to github.com → click "+" → "New repository"
2. Name it: securescan-backend
3. Set it to Private
4. Click "Create repository"

Then on your computer, open Terminal (Mac) or Command Prompt (Windows):

    cd path/to/securescan-railway
    git init
    git add .
    git commit -m "SecureScan backend — 57 security modules"
    git remote add origin https://github.com/YOUR_USERNAME/securescan-backend.git
    git push -u origin main

Replace YOUR_USERNAME with your actual GitHub username.


## STEP 2 — Create Railway project

1. Go to https://railway.app and sign in with GitHub
2. Click "New Project"
3. Choose "Deploy from GitHub repo"
4. Select your "securescan-backend" repo
5. Railway will auto-detect Python and start building

The first build takes about 2-3 minutes.


## STEP 3 — Add environment variables

In your Railway project:
1. Click on your service (the box that appeared)
2. Click the "Variables" tab
3. Click "Add Variable" for each one below:

┌─────────────────────────────────┬──────────────────────────────────────────┐
│ VARIABLE NAME                   │ WHERE TO GET IT                          │
├─────────────────────────────────┼──────────────────────────────────────────┤
│ SUPABASE_URL                    │ Supabase → Settings → API → Project URL  │
│ SUPABASE_SERVICE_KEY            │ Supabase → Settings → API → service_role │
│ SUPABASE_JWT_SECRET             │ Supabase → Settings → API → JWT Secret   │
│ STRIPE_SECRET_KEY               │ Stripe → Developers → API keys → Secret  │
│ STRIPE_WEBHOOK_SECRET           │ Stripe → Webhooks → signing secret       │
│ STRIPE_PRO_MONTHLY_PRICE_ID     │ Stripe → Products → your Pro plan        │
│ STRIPE_PRO_YEARLY_PRICE_ID      │ Stripe → Products → your Pro plan        │
│ STRIPE_TEAM_MONTHLY_PRICE_ID    │ Stripe → Products → your Team plan       │
│ STRIPE_TEAM_YEARLY_PRICE_ID     │ Stripe → Products → your Team plan       │
│ ANTHROPIC_API_KEY               │ console.anthropic.com → API Keys         │
│ SENDGRID_API_KEY                │ SendGrid → Settings → API Keys           │
│ FROM_EMAIL                      │ e.g. noreply@yourdomain.com              │
│ FROM_NAME                       │ SecureScan                               │
│ SECRET_KEY                      │ Any 32+ random characters (see below)    │
│ ENVIRONMENT                     │ production                               │
└─────────────────────────────────┴──────────────────────────────────────────┘

For SECRET_KEY — generate one free at: https://djecrety.ir

⚠️  IMPORTANT: Do NOT add APP_URL or ALLOWED_ORIGINS yet.
    Get your Railway URL first (Step 4), then come back and add them.


## STEP 4 — Get your live URL

1. Click the "Settings" tab in your Railway service
2. Scroll to "Networking" → click "Generate Domain"
3. Railway gives you a URL like:
   https://securescan-backend-production.up.railway.app

Copy that URL. Now go back to Variables and add:

│ APP_URL          │ https://securescan-backend-production.up.railway.app  │
│ ALLOWED_ORIGINS  │ https://securescan-backend-production.up.railway.app  │


## STEP 5 — Set up Supabase database

1. Go to your Supabase project
2. Click "SQL Editor" in the left sidebar
3. Click "New query"
4. Open the file: supabase_schema.sql (included in this package)
5. Copy the entire contents and paste into the SQL editor
6. Click "Run"

This creates all the tables SecureScan needs.


## STEP 6 — Set up Stripe webhook

Stripe needs to tell your app when payments happen.

1. Go to Stripe Dashboard → Developers → Webhooks
2. Click "Add endpoint"
3. Endpoint URL: https://YOUR-RAILWAY-URL/api/billing/webhook
4. Select these events:
   - customer.subscription.created
   - customer.subscription.updated
   - customer.subscription.deleted
   - invoice.payment_succeeded
   - invoice.payment_failed
5. Click "Add endpoint"
6. Copy the "Signing secret" → paste as STRIPE_WEBHOOK_SECRET in Railway


## STEP 7 — Test it's working

Open your browser and visit:
    https://your-railway-url.up.railway.app/health

You should see: {"status": "ok", "version": "2.0.0"}

Full API docs (development only):
    https://your-railway-url.up.railway.app/docs


## STEP 8 — Connect your mobile app

Open: mobile/src/lib/config.ts

Change the API_BASE line to your Railway URL:
    export const API_BASE = "https://securescan-backend-production.up.railway.app";

That's it. Your mobile app now talks to your live backend.


## SUPABASE SETUP (if you haven't already)

1. Go to https://supabase.com → "New project"
2. Name: securescan
3. Set a strong database password (save it somewhere)
4. Region: choose closest to your users
5. Click "Create new project" (takes ~2 min to provision)
6. Go to Settings → Authentication → enable "Email" provider
7. In Settings → API → copy:
   - Project URL → SUPABASE_URL
   - service_role key → SUPABASE_SERVICE_KEY
   - JWT Secret → SUPABASE_JWT_SECRET


## COSTS BREAKDOWN

Railway Starter: $5/month
  └─ Includes 512MB RAM, 1GB disk, 100GB bandwidth
  └─ Always on — no sleeping
  └─ Auto-deploys when you push to GitHub

Supabase Free tier: $0/month
  └─ 500MB database, 50MB file storage
  └─ 50,000 monthly active users
  └─ Pauses after 1 week of inactivity (upgrade to Pro $25/mo to prevent)

Stripe: 2.9% + 30¢ per transaction
  └─ No monthly fee

SendGrid Free: $0/month
  └─ 100 emails/day

Total to launch: ~$5/month


## TROUBLESHOOTING

Problem: Build fails with "No module named X"
Fix: Check requirements.txt is in the root of the uploaded folder

Problem: App crashes on start — "cannot connect to Supabase"
Fix: Double-check SUPABASE_URL and SUPABASE_SERVICE_KEY in Railway Variables
    Make sure you used the service_role key, NOT the anon key

Problem: Stripe webhooks failing
Fix: Make sure STRIPE_WEBHOOK_SECRET matches the signing secret from
    your Stripe webhook endpoint (not your API key)

Problem: Railway build succeeds but health check fails
Fix: Check the Deploy logs in Railway for Python errors
    Most common cause: missing environment variable

Problem: CORS errors from mobile app
Fix: Make sure ALLOWED_ORIGINS contains your exact Railway URL
    with no trailing slash

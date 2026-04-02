-- ══════════════════════════════════════════════════════════════════════════════
-- SecureScan — Complete Supabase Schema
-- Run this entire file in Supabase SQL Editor
-- ══════════════════════════════════════════════════════════════════════════════

-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- ── Profiles ──────────────────────────────────────────────────────────────────
create table if not exists profiles (
  id                  uuid primary key references auth.users(id) on delete cascade,
  email               text not null,
  full_name           text,
  plan                text not null default 'free' check (plan in ('free','pro','team')),
  stripe_customer_id  text unique,
  stripe_subscription_id text,
  subscription_status text default 'inactive',
  billing_cycle       text default 'monthly' check (billing_cycle in ('monthly','yearly')),
  scans_this_month    int not null default 0,
  scan_limit          int not null default 5,
  period_reset_at     timestamptz default (date_trunc('month', now()) + interval '1 month'),
  avatar_url          text,
  notification_email  boolean default true,
  created_at          timestamptz default now(),
  updated_at          timestamptz default now()
);

-- ── Scans ─────────────────────────────────────────────────────────────────────
create table if not exists scans (
  id              uuid primary key default uuid_generate_v4(),
  user_id         uuid not null references profiles(id) on delete cascade,
  url             text not null,
  hostname        text not null,
  status          text not null default 'queued' check (status in ('queued','running','complete','error')),
  score           int,
  grade           text,
  severity_counts jsonb default '{}',
  categories      jsonb default '[]',
  ai_summary      text,
  total_checks    int default 0,
  scan_duration_ms int,
  error_message   text,
  pdf_url         text,
  created_at      timestamptz default now(),
  updated_at      timestamptz default now()
);
create index if not exists scans_user_id_idx on scans(user_id);
create index if not exists scans_created_at_idx on scans(created_at desc);

-- ── Monitored Sites ───────────────────────────────────────────────────────────
create table if not exists monitored_sites (
  id               uuid primary key default uuid_generate_v4(),
  user_id          uuid not null references profiles(id) on delete cascade,
  url              text not null,
  interval_hours   int not null default 24,
  active           boolean default true,
  last_scanned_at  timestamptz,
  last_score       int,
  last_grade       text,
  last_scan_id     uuid,
  score_threshold  int default 70,
  created_at       timestamptz default now()
);
create index if not exists sites_user_id_idx on monitored_sites(user_id);

-- ── Alerts ────────────────────────────────────────────────────────────────────
create table if not exists alerts (
  id          uuid primary key default uuid_generate_v4(),
  user_id     uuid not null references profiles(id) on delete cascade,
  site_id     uuid references monitored_sites(id) on delete cascade,
  type        text not null check (type in ('score_drop','critical_finding','cert_expiry','scan_complete')),
  message     text not null,
  email_sent  boolean default false,
  read        boolean default false,
  sent_at     timestamptz default now()
);
create index if not exists alerts_user_id_idx on alerts(user_id);

-- ── API Keys ──────────────────────────────────────────────────────────────────
create table if not exists api_keys (
  id           uuid primary key default uuid_generate_v4(),
  user_id      uuid not null references profiles(id) on delete cascade,
  name         text not null,
  key_hash     text not null unique,
  key_prefix   text not null,
  active       boolean default true,
  last_used_at timestamptz,
  created_at   timestamptz default now()
);

-- ── Webhook Events (idempotency) ──────────────────────────────────────────────
create table if not exists webhook_events (
  id           text primary key,
  type         text not null,
  processed_at timestamptz default now()
);

-- ── RLS Policies ─────────────────────────────────────────────────────────────
alter table profiles        enable row level security;
alter table scans           enable row level security;
alter table monitored_sites enable row level security;
alter table alerts          enable row level security;
alter table api_keys        enable row level security;

-- Profiles
create policy "Users can view own profile"   on profiles for select using (auth.uid() = id);
create policy "Users can update own profile" on profiles for update using (auth.uid() = id);

-- Scans
create policy "Users can view own scans"   on scans for select using (auth.uid() = user_id);
create policy "Users can delete own scans" on scans for delete using (auth.uid() = user_id);

-- Monitored sites
create policy "Users can manage own sites" on monitored_sites for all using (auth.uid() = user_id);

-- Alerts
create policy "Users can view own alerts"  on alerts for select using (auth.uid() = user_id);
create policy "Users can update own alerts" on alerts for update using (auth.uid() = user_id);

-- API Keys
create policy "Users can manage own keys" on api_keys for all using (auth.uid() = user_id);

-- ── Auto-reset monthly scan counts ───────────────────────────────────────────
create or replace function reset_monthly_scans()
returns void language plpgsql as $$
begin
  update profiles
  set scans_this_month = 0,
      period_reset_at  = date_trunc('month', now()) + interval '1 month'
  where period_reset_at <= now();
end;
$$;

-- ── Updated_at trigger ────────────────────────────────────────────────────────
create or replace function update_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;
create trigger profiles_updated_at before update on profiles for each row execute function update_updated_at();
create trigger scans_updated_at    before update on scans    for each row execute function update_updated_at();

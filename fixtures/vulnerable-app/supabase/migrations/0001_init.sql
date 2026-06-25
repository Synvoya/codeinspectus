-- FIXTURE — planted issue #2: Supabase RLS failures.
-- Detected by: CodeInspectus AI supabase-rls check.

-- profiles: RLS enabled but with a USING (true) policy → fully open
-- (the CVE-2025-48757 signature). ci-ai-rls-using-true (critical, CWE-863).
create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  email text,
  full_name text
);

alter table public.profiles enable row level security;

create policy "profiles are viewable by everyone"
  on public.profiles
  for select
  using (true);

-- payments: created in public with NO row level security at all.
-- ci-ai-rls-missing (high, CWE-862).
create table public.payments (
  id uuid primary key,
  user_id uuid not null,
  amount_cents integer not null
);

-- accounts: a correctly-secured table — should NOT be flagged (precision check).
create table public.accounts (
  id uuid primary key,
  owner uuid not null,
  balance integer
);
alter table public.accounts enable row level security;
create policy "owners read their account"
  on public.accounts for select using (auth.uid() = owner);
create policy "owners update their account"
  on public.accounts for update using (auth.uid() = owner) with check (auth.uid() = owner);
create policy "owners insert their account"
  on public.accounts for insert with check (auth.uid() = owner);
create policy "owners delete their account"
  on public.accounts for delete using (auth.uid() = owner);

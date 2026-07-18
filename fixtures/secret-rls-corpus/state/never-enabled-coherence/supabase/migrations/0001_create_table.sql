create table public.audit_entries (
  id uuid primary key,
  account_id uuid not null
);

create table public.personal_exports (
  id uuid primary key,
  user_id uuid not null,
  email text
);
alter table public.personal_exports enable row level security;
create policy "public export writer" on public.personal_exports
  for insert with check (true);

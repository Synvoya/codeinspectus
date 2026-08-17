create table public.feedback (id uuid primary key, body text);
alter table public.feedback enable row level security;
drop policy if exists "public write" on public.feedback;
create policy "public write" on public.feedback
  for insert with check (true);

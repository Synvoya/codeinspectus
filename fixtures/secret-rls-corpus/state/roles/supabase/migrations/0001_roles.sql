create table public.integration_events (id uuid primary key);
alter table public.integration_events enable row level security;
create table public.feedback (id uuid primary key);
alter table public.feedback enable row level security;

create policy "service writer" on public.integration_events
  for insert to service_role with check (true);

create policy "public writer" on public.feedback
  for insert to anon, authenticated with check (true);

alter table public.external_audit disable row level security;
create policy "open external audit" on public.external_audit
  for select to anon using (true);

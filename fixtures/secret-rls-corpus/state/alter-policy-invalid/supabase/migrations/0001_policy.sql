create table public.invalid_alter_policy (id uuid primary key);
alter table public.invalid_alter_policy enable row level security;
create policy "select policy" on public.invalid_alter_policy for select to anon using (false);
alter policy "select policy" on public.invalid_alter_policy with check (true);

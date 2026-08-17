create table public.test_policy_table (id uuid primary key);
alter table public.test_policy_table enable row level security;
create policy "test-only open policy" on public.test_policy_table for select using (true);

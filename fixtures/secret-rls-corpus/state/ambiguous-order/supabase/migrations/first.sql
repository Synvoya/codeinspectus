create table public.ambiguous_table (id uuid primary key);
alter table public.ambiguous_table enable row level security;
create policy "open first" on public.ambiguous_table for select to anon using (true);

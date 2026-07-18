create table public.delivery_addresses (
  id uuid primary key,
  user_id uuid not null,
  address text
);
alter table public.delivery_addresses enable row level security;
create policy "temporary public reader" on public.delivery_addresses
  for select using (true);

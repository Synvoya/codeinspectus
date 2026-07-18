create table public.numeric_order_records (
  id uuid primary key,
  user_id uuid not null
);
alter table public.numeric_order_records enable row level security;
create policy "numeric reader" on public.numeric_order_records
  for select using (true);

create table public.customer_records (
  id uuid primary key,
  user_id uuid not null,
  email text
);

alter table public.customer_records enable row level security;

create policy "customer records insert"
  on public.customer_records
  for insert
  with check (true);

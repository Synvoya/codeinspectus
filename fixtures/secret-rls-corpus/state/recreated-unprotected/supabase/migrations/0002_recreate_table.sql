drop table public.delivery_addresses;
create table public.delivery_addresses (
  id uuid primary key,
  user_id uuid not null,
  address text
);

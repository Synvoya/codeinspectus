create table public.products (
  id uuid primary key,
  name text not null,
  price numeric not null
);
alter table public.products enable row level security;

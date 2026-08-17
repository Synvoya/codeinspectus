create table public.documents (
  id uuid primary key,
  owner_id uuid not null
);
alter table public.documents enable row level security;

create policy "document reader" on public.documents
  for select using (auth.uid() = owner_id);

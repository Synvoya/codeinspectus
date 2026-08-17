create table public.inverted_or_documents (
  id uuid primary key,
  user_id uuid not null
);
alter table public.inverted_or_documents enable row level security;
create policy "role branch bypasses ownership" on public.inverted_or_documents
  for select to authenticated
  using (auth.role() = 'authenticated' or auth.uid() = user_id);

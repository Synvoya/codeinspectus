create table public.private_notes (
  id uuid primary key,
  user_id uuid not null,
  secret text
);
alter table public.private_notes enable row level security;
create policy "owners insert notes" on public.private_notes
  for select using (auth.uid() = user_id);

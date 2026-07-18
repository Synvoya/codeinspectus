create table public."Account Records" (
  id uuid primary key,
  user_id uuid not null,
  email text
);
alter table public."Account Records" enable row level security;

create policy "Temporary Public Reader"
  on public."Account Records"
  for select
  using (true);

create policy "Retained Public Reader"
  on public."Account Records"
  for select
  using (true);

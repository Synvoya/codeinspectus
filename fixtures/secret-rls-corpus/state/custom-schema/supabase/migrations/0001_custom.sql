create table api_private.documents (id uuid primary key);
alter table api_private.documents enable row level security;
create policy "custom schema open" on api_private.documents for select to anon using (true);

create table public.old_private_notes (id uuid primary key, user_id uuid not null);
alter table public.old_private_notes enable row level security;
create policy "open renamed notes" on public.old_private_notes for select to anon using (true);
alter table public.old_private_notes rename to renamed_private_notes;

create table internal.internal_events (id uuid primary key);
alter table internal.internal_events enable row level security;
create policy "open moved events" on internal.internal_events for insert to authenticated with check (true);
alter table internal.internal_events set schema public;

create table public.moved_out (id uuid primary key);
alter table public.moved_out enable row level security;
create policy "open but moved out" on public.moved_out for select to anon using (true);
alter table public.moved_out set schema internal;

create table public.old_unprotected (id uuid primary key);
alter table public.old_unprotected rename to renamed_unprotected;

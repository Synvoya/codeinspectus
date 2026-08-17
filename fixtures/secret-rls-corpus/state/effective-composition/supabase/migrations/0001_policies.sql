create table public.anon_only_open (id uuid primary key, user_id uuid not null);
alter table public.anon_only_open enable row level security;
create policy "public base" on public.anon_only_open
  as permissive for select to public using (true);
create policy "authenticated restriction" on public.anon_only_open
  as restrictive for select to authenticated using (auth.uid() = user_id);

create table public.restrictive_blocks (id uuid primary key, user_id uuid not null);
alter table public.restrictive_blocks enable row level security;
create policy "open base" on public.restrictive_blocks
  as permissive for select to anon using (true);
create policy "ownership restriction" on public.restrictive_blocks
  as restrictive for select to anon using (auth.uid() = user_id);

create table public.or_composition (id uuid primary key);
alter table public.or_composition enable row level security;
create policy "closed branch" on public.or_composition
  as permissive for insert to anon with check (false);
create policy "open branch" on public.or_composition
  as permissive for insert to anon with check (((true)::boolean));
create policy "true restriction" on public.or_composition
  as restrictive for insert to anon with check (true);

create table public.no_permissive (id uuid primary key);
alter table public.no_permissive enable row level security;
create policy "restriction only" on public.no_permissive
  as restrictive for select to anon using (true);

create table public.literal_decoys (id uuid primary key, "true" boolean);
alter table public.literal_decoys enable row level security;
create policy "string decoy" on public.literal_decoys for select to anon using ('true' = 'true');
create policy "quoted identifier decoy" on public.literal_decoys for select to authenticated using ("true");

create table public.invalid_clause_shapes (id uuid primary key);
alter table public.invalid_clause_shapes enable row level security;
create policy "invalid insert using" on public.invalid_clause_shapes for insert to anon using (true);
create policy "invalid select check" on public.invalid_clause_shapes for select to authenticated with check (true);

create table public.default_open (id uuid primary key);
alter table public.default_open enable row level security;
create policy "default true visibility" on public.default_open for select to anon;

create table public.partial_update (id uuid primary key, user_id uuid not null);
alter table public.partial_update enable row level security;
create policy "check alone is not enough" on public.partial_update
  for update to anon using (auth.uid() = user_id) with check (true);

create table public.open_update (id uuid primary key, user_id uuid not null);
alter table public.open_update enable row level security;
create policy "both update phases open" on public.open_update
  for update to authenticated using (true) with check (true);

create table public.numeric_true (id uuid primary key);
alter table public.numeric_true enable row level security;
create policy "numeric equality is open" on public.numeric_true
  for select to anon using (((1 = 1)));

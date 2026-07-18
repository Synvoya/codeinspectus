drop policy if exists "public write" on public.feedback;
create policy "public write" on public.feedback
  for insert with check (true);

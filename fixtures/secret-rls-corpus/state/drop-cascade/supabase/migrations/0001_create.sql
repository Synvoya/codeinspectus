create policy "temporary cascade writer" on public.cascade_records
  for insert with check (true);

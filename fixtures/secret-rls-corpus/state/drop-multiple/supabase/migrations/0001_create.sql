create policy "first temporary writer" on public.first_drop_records
  for insert with check (true);
create policy "second temporary writer" on public.second_drop_records
  for insert with check (true);

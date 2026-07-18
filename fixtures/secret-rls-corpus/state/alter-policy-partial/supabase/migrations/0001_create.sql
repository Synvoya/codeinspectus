create policy "partial update writer" on public.partial_records
  for update
  using (auth.uid() = user_id)
  with check (true);

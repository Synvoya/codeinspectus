alter policy "partial update writer" on public.partial_records
  using (auth.uid() = owner_id);

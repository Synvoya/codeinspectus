create policy "document reader" on public.documents
  for select using (auth.uid() = owner_id);

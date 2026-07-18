drop policy "document reader" on public.documents;
create policy "document reader" on public.documents
  for select using (auth.jwt() ->> 'role' = 'authenticated');

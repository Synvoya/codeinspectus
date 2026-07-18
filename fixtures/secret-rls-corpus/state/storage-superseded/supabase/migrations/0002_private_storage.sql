drop policy if exists "public uploads" on storage.objects;
create policy "public uploads" on storage.objects
  for insert with check (auth.uid() = owner);

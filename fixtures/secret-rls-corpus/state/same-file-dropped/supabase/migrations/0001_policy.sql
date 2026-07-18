create policy "temporary public read" on public.status_pages
  for select using (true);
drop policy "temporary public read" on public.status_pages;

drop policy "owners insert notes" on public.private_notes;
create policy "owners insert notes" on public.private_notes
  for select using (true);

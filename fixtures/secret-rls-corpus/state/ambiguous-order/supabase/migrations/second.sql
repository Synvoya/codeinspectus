drop policy "open first" on public.ambiguous_table;
create policy "closed second" on public.ambiguous_table for select to anon using (auth.uid() = id);

create policy "account reader" on public.account_rows
  for select using (auth.role() = 'authenticated');

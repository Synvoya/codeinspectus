drop policy "account reader" on public.account_rows;
create policy "account reader" on public.account_rows
  for select using (auth.uid() = user_id);

drop policy "numeric reader" on public.numeric_order_records;
create policy "numeric reader" on public.numeric_order_records
  for select using (auth.uid() = user_id);

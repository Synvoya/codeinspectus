drop policy if exists "customer records insert" on public.customer_records;

create policy "customer records insert"
  on public.customer_records
  for insert
  with check (auth.uid() = user_id);

create or replace function public.policy_template()
returns void
language sql
as $policy_template$
create policy "generated public writer" on public.dollar_body_records
  for insert with check (true);
$policy_template$;

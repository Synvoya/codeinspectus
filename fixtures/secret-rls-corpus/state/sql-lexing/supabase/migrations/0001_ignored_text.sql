/*
create policy "commented public writer" on public.comment_records
  for insert with check (true);
*/

create or replace function public.policy_template()
returns text
language plpgsql
as $$
begin
  return 'create policy "generated public writer" on public.generated_records for insert with check (true);';
end;
$$;

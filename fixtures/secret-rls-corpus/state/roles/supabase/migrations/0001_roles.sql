create policy "service writer" on public.integration_events
  for insert to service_role with check (true);

create policy "public writer" on public.feedback
  for insert to anon, authenticated with check (true);
